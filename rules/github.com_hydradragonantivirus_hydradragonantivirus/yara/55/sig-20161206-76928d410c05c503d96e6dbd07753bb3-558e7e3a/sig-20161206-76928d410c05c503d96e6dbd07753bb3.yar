rule sig_20161206_76928d410c05c503d96e6dbd07753bb3 {
  meta:
    description = "datamaliciousorder - file 20161206_76928d410c05c503d96e6dbd07753bb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "721b9e4b61e93c3c34cbce6271ec501b645f354c670034980599018199bd0b43"

  strings:
    $s1 = "function _IQh2(s) {var _GXc1 = new Date();_GXc1.setUTCFullYear(\"2003\");if (_GXc1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IQh2(s) {var _GXc1 = new Date();_GXc1.setUTCFullYear(\"2003\");if (_GXc1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Gh0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}