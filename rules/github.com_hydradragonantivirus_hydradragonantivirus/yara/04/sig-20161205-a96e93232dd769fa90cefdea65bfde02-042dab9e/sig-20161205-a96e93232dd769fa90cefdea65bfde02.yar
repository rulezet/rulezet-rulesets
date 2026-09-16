rule sig_20161205_a96e93232dd769fa90cefdea65bfde02 {
  meta:
    description = "datamaliciousorder - file 20161205_a96e93232dd769fa90cefdea65bfde02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d7d2603cdd200ab6ea276341e882ed2076ee51380fc18228e2ffbff49566d4"

  strings:
    $s1 = "function _Ga4(s) {var _Ye9 = new Date();_Ye9.setUTCFullYear(\"2003\");if (_Ye9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ga4(s) {var _Ye9 = new Date();_Ye9.setUTCFullYear(\"2003\");if (_Ye9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _QQw5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}