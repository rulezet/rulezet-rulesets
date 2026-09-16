rule sig_20161205_4a9a0ffeb0752c3b2439bccca04780e0 {
  meta:
    description = "datamaliciousorder - file 20161205_4a9a0ffeb0752c3b2439bccca04780e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63eecafa7463e6b516febdc071d36044ae6221e7af1ed7e1aeba20d95bf41290"

  strings:
    $s1 = "function _Wb7(s) {var _OLt6 = new Date();_OLt6.setUTCFullYear(\"2003\");if (_OLt6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Wb7(s) {var _OLt6 = new Date();_OLt6.setUTCFullYear(\"2003\");if (_OLt6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Po4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}