rule sig_20161205_788b8d2af44852c120ac8088bf34fa50 {
  meta:
    description = "datamaliciousorder - file 20161205_788b8d2af44852c120ac8088bf34fa50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0719d012188181d6be4dace73e48a721f7c2e69c96a9ffcc0915558e6df18d67"

  strings:
    $s1 = "function _XTd3(s) {var _NOa7 = new Date();_NOa7.setUTCFullYear(\"2003\");if (_NOa7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XTd3(s) {var _NOa7 = new Date();_NOa7.setUTCFullYear(\"2003\");if (_NOa7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _No7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}