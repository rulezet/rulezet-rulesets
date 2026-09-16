rule sig_20161205_b30b1f89aeb76c7617524c9bbc7aed5c {
  meta:
    description = "datamaliciousorder - file 20161205_b30b1f89aeb76c7617524c9bbc7aed5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caa27c72f49697261d79643982f55ff7b73c0775ca8bbcb1e3ee269447f456a2"

  strings:
    $s1 = "function _ESv8(s) {var _LIr9 = new Date();_LIr9.setUTCFullYear(\"2003\");if (_LIr9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ESv8(s) {var _LIr9 = new Date();_LIr9.setUTCFullYear(\"2003\");if (_LIr9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Qr0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}