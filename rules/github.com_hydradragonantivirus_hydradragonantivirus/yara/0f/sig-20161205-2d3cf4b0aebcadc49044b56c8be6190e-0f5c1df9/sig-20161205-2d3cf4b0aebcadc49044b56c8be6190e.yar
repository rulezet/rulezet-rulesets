rule sig_20161205_2d3cf4b0aebcadc49044b56c8be6190e {
  meta:
    description = "datamaliciousorder - file 20161205_2d3cf4b0aebcadc49044b56c8be6190e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9ee682fbcf73aaf0c375594740a1aea7cd2f376c318f417a1b5018e307c6984"

  strings:
    $s1 = "function _DFg8(s) {var _IRv4 = new Date();_IRv4.setUTCFullYear(\"2003\");if (_IRv4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _DFg8(s) {var _IRv4 = new Date();_IRv4.setUTCFullYear(\"2003\");if (_IRv4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ge1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}