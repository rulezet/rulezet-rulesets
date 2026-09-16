rule sig_20161205_4becc6611dcb44fc1d8f5a728303ada1 {
  meta:
    description = "datamaliciousorder - file 20161205_4becc6611dcb44fc1d8f5a728303ada1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "753d6a006d627c7e11ed40900b06d956aa1cecfd8c307441abfd3292d97face7"

  strings:
    $s1 = "function _Bq2(s) {var _Qv6 = new Date();_Qv6.setUTCFullYear(\"2003\");if (_Qv6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bq2(s) {var _Qv6 = new Date();_Qv6.setUTCFullYear(\"2003\");if (_Qv6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Fj8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}