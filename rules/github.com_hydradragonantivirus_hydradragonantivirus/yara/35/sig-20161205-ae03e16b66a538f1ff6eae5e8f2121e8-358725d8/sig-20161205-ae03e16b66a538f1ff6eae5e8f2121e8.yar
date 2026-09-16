rule sig_20161205_ae03e16b66a538f1ff6eae5e8f2121e8 {
  meta:
    description = "datamaliciousorder - file 20161205_ae03e16b66a538f1ff6eae5e8f2121e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8aac40a74ac86e8b532c34a01802ebe6988f8b6e604b2d7f2a50beaabff5f94"

  strings:
    $s1 = "function _DLf2(s) {var _Tl8 = new Date();_Tl8.setUTCFullYear(\"2003\");if (_Tl8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DLf2(s) {var _Tl8 = new Date();_Tl8.setUTCFullYear(\"2003\");if (_Tl8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vc0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}