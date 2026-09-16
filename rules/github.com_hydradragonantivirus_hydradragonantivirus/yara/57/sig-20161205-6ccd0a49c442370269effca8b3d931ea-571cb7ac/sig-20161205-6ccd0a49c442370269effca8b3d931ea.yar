rule sig_20161205_6ccd0a49c442370269effca8b3d931ea {
  meta:
    description = "datamaliciousorder - file 20161205_6ccd0a49c442370269effca8b3d931ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e8782dc028e61ced88227aa2038703732e2d70d1e3b151a9ecf17005c96519f"

  strings:
    $s1 = "function _XSb9(s) {var _NYi8 = new Date();_NYi8.setUTCFullYear(\"2003\");if (_NYi8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XSb9(s) {var _NYi8 = new Date();_NYi8.setUTCFullYear(\"2003\");if (_NYi8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Bn6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}