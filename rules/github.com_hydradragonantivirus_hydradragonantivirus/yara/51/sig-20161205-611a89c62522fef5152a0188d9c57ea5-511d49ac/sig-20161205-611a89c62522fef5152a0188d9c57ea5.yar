rule sig_20161205_611a89c62522fef5152a0188d9c57ea5 {
  meta:
    description = "datamaliciousorder - file 20161205_611a89c62522fef5152a0188d9c57ea5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d764477b9426261485e6af3f141350ad747c3b8c2ead0e24ea9895a2ad62f211"

  strings:
    $s1 = "function _YMu6(s) {var _Kd1 = new Date();_Kd1.setUTCFullYear(\"2003\");if (_Kd1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YMu6(s) {var _Kd1 = new Date();_Kd1.setUTCFullYear(\"2003\");if (_Kd1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TJq6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}