rule sig_20161205_a4a47589efc585e7b4e3a462afe2f75f {
  meta:
    description = "datamaliciousorder - file 20161205_a4a47589efc585e7b4e3a462afe2f75f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55d071c4aaf8e56eb3a02329c89ec1c85f30dc24487d25e03abfcfd914234fbb"

  strings:
    $s1 = "function _XBi5(s) {var _Yq9 = new Date();_Yq9.setUTCFullYear(\"2003\");if (_Yq9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _XBi5(s) {var _Yq9 = new Date();_Yq9.setUTCFullYear(\"2003\");if (_Yq9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Eb5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}