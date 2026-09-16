rule sig_20161205_a2c17e1511941da4b56656b70ac09cd5 {
  meta:
    description = "datamaliciousorder - file 20161205_a2c17e1511941da4b56656b70ac09cd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b91998ba4a9b4ec192def7b2548fff3fbfad9d2ae300dce4a40b1c88e8f0b44"

  strings:
    $s1 = "function _XWe8(s) {var _ZXi0 = new Date();_ZXi0.setUTCFullYear(\"2003\");if (_ZXi0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XWe8(s) {var _ZXi0 = new Date();_ZXi0.setUTCFullYear(\"2003\");if (_ZXi0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Zz7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}