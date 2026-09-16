rule sig_20161206_d5a1538078d155d8350be6def5760862 {
  meta:
    description = "datamaliciousorder - file 20161206_d5a1538078d155d8350be6def5760862.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36b7e4d9f36cab3c3bc13dc9d3a05f917230d71c7cb3552897e7c4e8b0e817b9"

  strings:
    $s1 = "function _Pv3(s) {var _Dk6 = new Date();_Dk6.setUTCFullYear(\"2003\");if (_Dk6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pv3(s) {var _Dk6 = new Date();_Dk6.setUTCFullYear(\"2003\");if (_Dk6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _BVd1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}