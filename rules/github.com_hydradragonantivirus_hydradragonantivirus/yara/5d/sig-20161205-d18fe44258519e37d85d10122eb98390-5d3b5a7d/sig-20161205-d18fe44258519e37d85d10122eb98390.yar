rule sig_20161205_d18fe44258519e37d85d10122eb98390 {
  meta:
    description = "datamaliciousorder - file 20161205_d18fe44258519e37d85d10122eb98390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "578d03c60294b52cd2509220c6d1b259b28373a86f4df09a19e59ba55bfd2f6d"

  strings:
    $s1 = "function _WXc3(s) {var _NKy1 = new Date();_NKy1.setUTCFullYear(\"2003\");if (_NKy1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WXc3(s) {var _NKy1 = new Date();_NKy1.setUTCFullYear(\"2003\");if (_NKy1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WPw0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}