rule sig_20161205_e33de6c141949f4b622f5534909fdc5f {
  meta:
    description = "datamaliciousorder - file 20161205_e33de6c141949f4b622f5534909fdc5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffe93f00c03069489c5b0ddb7c1b2704dfbaf88ba68df9240f439cbe917c8cc9"

  strings:
    $s1 = "function _Pl9(s) {var _SWy9 = new Date();_SWy9.setUTCFullYear(\"2003\");if (_SWy9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Pl9(s) {var _SWy9 = new Date();_SWy9.setUTCFullYear(\"2003\");if (_SWy9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FAt9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}