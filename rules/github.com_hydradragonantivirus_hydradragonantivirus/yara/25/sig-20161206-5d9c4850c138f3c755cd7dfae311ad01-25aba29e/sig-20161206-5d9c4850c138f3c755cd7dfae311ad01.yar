rule sig_20161206_5d9c4850c138f3c755cd7dfae311ad01 {
  meta:
    description = "datamaliciousorder - file 20161206_5d9c4850c138f3c755cd7dfae311ad01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d32699db7ae8804ca2503dec13bdec5b6294c1e8a9cd54a4e6aa3aecefe379c"

  strings:
    $s1 = "function _CZk1(s) {var _AIw0 = new Date();_AIw0.setUTCFullYear(\"2003\");if (_AIw0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CZk1(s) {var _AIw0 = new Date();_AIw0.setUTCFullYear(\"2003\");if (_AIw0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Bu5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}