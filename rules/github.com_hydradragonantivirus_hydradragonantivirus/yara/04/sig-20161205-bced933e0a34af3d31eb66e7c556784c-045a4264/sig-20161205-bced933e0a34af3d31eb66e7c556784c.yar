rule sig_20161205_bced933e0a34af3d31eb66e7c556784c {
  meta:
    description = "datamaliciousorder - file 20161205_bced933e0a34af3d31eb66e7c556784c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b001d972abfe2edc9f0de5c4b4afca827e35e50b46ac096f70a3a5f30d68c39a"

  strings:
    $s1 = "function _Dy3(s) {var _Jd6 = new Date();_Jd6.setUTCFullYear(\"2003\");if (_Jd6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dy3(s) {var _Jd6 = new Date();_Jd6.setUTCFullYear(\"2003\");if (_Jd6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PYc5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}