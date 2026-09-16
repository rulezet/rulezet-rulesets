rule sig_20161205_0560ba9a8b8dd5230d98a199ab7a4a9d {
  meta:
    description = "datamaliciousorder - file 20161205_0560ba9a8b8dd5230d98a199ab7a4a9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3207edc69c4cb1e40d58c27a0b36454fb99fbb54b1428e20ebbaac608b94931a"

  strings:
    $s1 = "function _Hn1(s) {var _WDf4 = new Date();_WDf4.setUTCFullYear(\"2003\");if (_WDf4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hn1(s) {var _WDf4 = new Date();_WDf4.setUTCFullYear(\"2003\");if (_WDf4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ox0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}