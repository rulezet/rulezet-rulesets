rule sig_20161205_882f9c7396b2642b2f43f9ea84c89fe0 {
  meta:
    description = "datamaliciousorder - file 20161205_882f9c7396b2642b2f43f9ea84c89fe0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3414936ea89945858f47f41af80e03d772a79f1452400961c8754049977c25"

  strings:
    $s1 = "function _ZQb2(s) {var _BEb4 = new Date();_BEb4.setUTCFullYear(\"2003\");if (_BEb4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZQb2(s) {var _BEb4 = new Date();_BEb4.setUTCFullYear(\"2003\");if (_BEb4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Eu9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}