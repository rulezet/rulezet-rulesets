rule sig_20161205_5f145e43d089705bd59e980cd87bc979 {
  meta:
    description = "datamaliciousorder - file 20161205_5f145e43d089705bd59e980cd87bc979.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05c1537666683695fd00f75c45357d026b29fc2416368d2d8118f6f6690212ef"

  strings:
    $s1 = "function _Eo5(s) {var _Ur7 = new Date();_Ur7.setUTCFullYear(\"2003\");if (_Ur7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Eo5(s) {var _Ur7 = new Date();_Ur7.setUTCFullYear(\"2003\");if (_Ur7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _DJn5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}