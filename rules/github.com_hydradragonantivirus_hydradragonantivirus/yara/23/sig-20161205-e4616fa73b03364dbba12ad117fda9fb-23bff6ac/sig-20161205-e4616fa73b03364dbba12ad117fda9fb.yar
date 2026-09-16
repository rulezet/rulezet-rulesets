rule sig_20161205_e4616fa73b03364dbba12ad117fda9fb {
  meta:
    description = "datamaliciousorder - file 20161205_e4616fa73b03364dbba12ad117fda9fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecaf7f67078a7b67719a0ae295fe3dcf0cfeff8e9185f310aa7c2c301c2997da"

  strings:
    $s1 = "function _Sz8(s) {var _WXw7 = new Date();_WXw7.setUTCFullYear(\"2003\");if (_WXw7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sz8(s) {var _WXw7 = new Date();_WXw7.setUTCFullYear(\"2003\");if (_WXw7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Un7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}