rule sig_20161206_4051782c5857b23847e22f8e03364041 {
  meta:
    description = "datamaliciousorder - file 20161206_4051782c5857b23847e22f8e03364041.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23346bc6e385ac9dcd1c0de274b0a92ee749da4f7a5a7dbeed7bd14bad3ce943"

  strings:
    $s1 = "function _VDy8(s) {var _NOv0 = new Date();_NOv0.setUTCFullYear(\"2003\");if (_NOv0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VDy8(s) {var _NOv0 = new Date();_NOv0.setUTCFullYear(\"2003\");if (_NOv0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Qo8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}