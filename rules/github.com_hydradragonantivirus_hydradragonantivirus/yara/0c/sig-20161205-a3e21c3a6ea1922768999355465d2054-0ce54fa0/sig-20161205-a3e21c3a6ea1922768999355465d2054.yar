rule sig_20161205_a3e21c3a6ea1922768999355465d2054 {
  meta:
    description = "datamaliciousorder - file 20161205_a3e21c3a6ea1922768999355465d2054.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a936054a69295f1cb0a14e11daa65b5650a0ab500a43b29a780675d665ddfdd"

  strings:
    $s1 = "function _Ei2(s) {var _SNd8 = new Date();_SNd8.setUTCFullYear(\"2003\");if (_SNd8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ei2(s) {var _SNd8 = new Date();_SNd8.setUTCFullYear(\"2003\");if (_SNd8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TDw0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}