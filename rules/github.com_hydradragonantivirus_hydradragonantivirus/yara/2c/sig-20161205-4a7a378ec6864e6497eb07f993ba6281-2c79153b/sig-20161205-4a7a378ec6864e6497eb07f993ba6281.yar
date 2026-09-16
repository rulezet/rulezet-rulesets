rule sig_20161205_4a7a378ec6864e6497eb07f993ba6281 {
  meta:
    description = "datamaliciousorder - file 20161205_4a7a378ec6864e6497eb07f993ba6281.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd3372d348bd7bf406baca0a2360bdf5a8fe9e5b9a0f7000b3530b048f5187f8"

  strings:
    $s1 = "function _Jf1(s) {var _Yz5 = new Date();_Yz5.setUTCFullYear(\"2003\");if (_Yz5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jf1(s) {var _Yz5 = new Date();_Yz5.setUTCFullYear(\"2003\");if (_Yz5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _BHb0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}