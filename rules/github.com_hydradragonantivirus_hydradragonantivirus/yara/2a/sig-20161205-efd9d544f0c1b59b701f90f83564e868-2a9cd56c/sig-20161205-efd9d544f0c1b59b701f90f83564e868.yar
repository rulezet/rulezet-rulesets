rule sig_20161205_efd9d544f0c1b59b701f90f83564e868 {
  meta:
    description = "datamaliciousorder - file 20161205_efd9d544f0c1b59b701f90f83564e868.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e8ca3c4fe1731979c89c1eb76167a9620761f51fbb6152c8b78c2d2bb01fce9"

  strings:
    $s1 = "function _Cd6(s) {var _Mm8 = new Date();_Mm8.setUTCFullYear(\"2003\");if (_Mm8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cd6(s) {var _Mm8 = new Date();_Mm8.setUTCFullYear(\"2003\");if (_Mm8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HXj2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}