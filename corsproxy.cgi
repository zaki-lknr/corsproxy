#!/usr/bin/env perl
use strict;
use warnings;

use CGI;
use LWP::UserAgent;
use HTTP::Request;
use URI;
use HTTP::Cookies;

# =========================
# 設定
# =========================
my $TIMEOUT = 10;

# 許可ドメイン制限
my @ALLOW_HOST_REGEX = (
    qr/^(?:[a-z0-9-]+\.)*swarmapp\.com$/,
    qr/^(?:[a-z0-9-]+\.)*foursquare\.com$/,
);

# =========================
# CGI 初期化
# =========================
my $cgi = CGI->new;

# -------------------------
# OPTIONS（CORS プリフライト）
# -------------------------
if ($ENV{REQUEST_METHOD} eq 'OPTIONS') {
    print "Status: 204 No Content\r\n";
    print "Access-Control-Allow-Origin: *\r\n";
    print "Access-Control-Allow-Headers: *\r\n";
    print "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    print "Access-Control-Max-Age: 86400\r\n\r\n";
    exit;
}

# =========================
# URL パラメータ
# =========================
my $url = $cgi->param('url');
unless ($url) {
    print "Status: 400 Bad Request\r\n";
    print "Content-Type: text/plain\r\n\r\n";
    print "url parameter is required\n";
    exit;
}

my $uri = URI->new($url);

# -------------------------
# URL 検証
# -------------------------
unless ($uri->scheme =~ /^https?$/) {
    print "Status: 400 Bad Request\r\n";
    print "Content-Type: text/plain\r\n\r\n";
    print "Only http/https allowed\n";
    exit;
}

my $host = lc( defined($uri->host) ? $uri->host : '' );

# SSRF 対策（内部アドレス遮断）
if ($host =~ /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/) {
    print "Status: 403 Forbidden\r\n";
    print "Content-Type: text/plain\r\n\r\n";
    print "Access denied\n";
    exit;
}

# 許可ドメイン制限
my $ok = 0;
for (@ALLOW_HOST_REGEX) {
    if ($host =~ $_) {
        $ok = 1;
        last;
    }
}
if (!$ok) {
    print "Status: 403 Forbidden\r\n";
    print "Content-Type: text/plain\r\n\r\n";
    print "Host not allowed: $host\n";
    exit;
}

# =========================
# UserAgent 設定
# =========================
my $ua = LWP::UserAgent->new(
    timeout => $TIMEOUT,
    agent   => $ENV{HTTP_USER_AGENT} || 'My-CORS-Proxy/1.0',
);

# Cookie 管理
my $cookie_jar = HTTP::Cookies->new;
$ua->cookie_jar($cookie_jar);

# =========================
# リクエスト作成
# =========================
my $method = $ENV{REQUEST_METHOD} || 'GET';
my $req    = HTTP::Request->new($method => $url);

# -------------------------
# ヘッダ透過（ホワイトリスト）
# -------------------------
my @PASS_HEADERS = qw(
    Accept
    Accept-Language
    User-Agent
    Referer
);

for my $h (@PASS_HEADERS) {
    my $env = 'HTTP_' . uc($h);
    $env =~ s/-/_/g;
    $req->header($h => $ENV{$env}) if $ENV{$env};
}

# # Cookie 透過
# $req->header('Cookie' => $ENV{HTTP_COOKIE}) if $ENV{HTTP_COOKIE};

# POST データ透過
if ($method eq 'POST') {
    my $content = $cgi->param('POSTDATA');
    $req->content($content) if defined $content;
    $req->header(
        'Content-Type' => $ENV{CONTENT_TYPE}
    ) if $ENV{CONTENT_TYPE};
}

# =========================
# 外部リクエスト実行
# =========================
my $res = $ua->request($req);

# =========================
# レスポンス返却
# =========================
print "Status: " . $res->code . "\r\n";

# Content-Type
print "Content-Type: "
    . ($res->header('Content-Type') || 'application/octet-stream')
    . "\r\n";

# Set-Cookie 透過
for my $sc ($res->header('Set-Cookie')) {
    print "Set-Cookie: $sc\r\n" if $sc;
}

# CORS ヘッダ
print "Access-Control-Allow-Origin: *\r\n";
print "Access-Control-Allow-Headers: *\r\n";
print "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";

print "\r\n";
print $res->content;

exit;
