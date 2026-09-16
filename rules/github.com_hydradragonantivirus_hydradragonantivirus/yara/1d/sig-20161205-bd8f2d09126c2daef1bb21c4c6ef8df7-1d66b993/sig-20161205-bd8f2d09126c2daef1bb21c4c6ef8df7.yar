rule sig_20161205_bd8f2d09126c2daef1bb21c4c6ef8df7 {
  meta:
    description = "datamaliciousorder - file 20161205_bd8f2d09126c2daef1bb21c4c6ef8df7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e0fe8931837ac034c5b62804ab98aff748c6e8100d7115531b938eb165f93f6"

  strings:
    $s1 = "function _FSr3(s) {var _FDk1 = new Date();_FDk1.setUTCFullYear(\"2003\");if (_FDk1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FSr3(s) {var _FDk1 = new Date();_FDk1.setUTCFullYear(\"2003\");if (_FDk1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ml1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}