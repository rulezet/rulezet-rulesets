rule sig_20161205_040e797d48c0ec0fab9c7af55252e7ea {
  meta:
    description = "datamaliciousorder - file 20161205_040e797d48c0ec0fab9c7af55252e7ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "185afbb3b6c5133195da2c034108ebc1d354749f15ef1b7edb4f3b3a4c67b493"

  strings:
    $s1 = "function _Ye7(s) {var _Th7 = new Date();_Th7.setUTCFullYear(\"2003\");if (_Th7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ye7(s) {var _Th7 = new Date();_Th7.setUTCFullYear(\"2003\");if (_Th7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _KBu0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}