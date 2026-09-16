rule sig_20161206_8bb71f2a7d8e9b197c6c24ca37eed8d6 {
  meta:
    description = "datamaliciousorder - file 20161206_8bb71f2a7d8e9b197c6c24ca37eed8d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b5ee9d24bbe10b394226cf167a65006b529379f8d383fc4589429c7ffc0ba2f"

  strings:
    $s1 = "function _Qo6(s) {var _SKn1 = new Date();_SKn1.setUTCFullYear(\"2003\");if (_SKn1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qo6(s) {var _SKn1 = new Date();_SKn1.setUTCFullYear(\"2003\");if (_SKn1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YNq0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}