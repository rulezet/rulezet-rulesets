rule sig_20161206_d0adffcce8193200bf5b585181d2de50 {
  meta:
    description = "datamaliciousorder - file 20161206_d0adffcce8193200bf5b585181d2de50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae8ee7b19c7ee2725f6713a3184f49df2d07923e0ad7ea4d720a6cd033016741"

  strings:
    $s1 = "function _Qk6(s) {var _Oe9 = new Date();_Oe9.setUTCFullYear(\"2003\");if (_Oe9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qk6(s) {var _Oe9 = new Date();_Oe9.setUTCFullYear(\"2003\");if (_Oe9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Tu3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}