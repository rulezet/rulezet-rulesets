rule sig_20161206_1bf599e1d06806257a1894b50fd4a552 {
  meta:
    description = "datamaliciousorder - file 20161206_1bf599e1d06806257a1894b50fd4a552.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "493b5e734d7cf1e7ecd015bd97aba506079b739866847b2508fd5ee643a31098"

  strings:
    $s1 = "function _RPr6(s) {var _GPj6 = new Date();_GPj6.setUTCFullYear(\"2003\");if (_GPj6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _RPr6(s) {var _GPj6 = new Date();_GPj6.setUTCFullYear(\"2003\");if (_GPj6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _MWv4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}