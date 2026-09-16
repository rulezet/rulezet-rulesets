rule sig_20161206_d5aa377f4b899a9bb1fd7a7ff476b3b0 {
  meta:
    description = "datamaliciousorder - file 20161206_d5aa377f4b899a9bb1fd7a7ff476b3b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "548e5a84b62806edfe16014ab503d8996489afb5acf2df736cde6e5dbb315f44"

  strings:
    $s1 = "function _Ef8(s) {var _YKc2 = new Date();_YKc2.setUTCFullYear(\"2003\");if (_YKc2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ef8(s) {var _YKc2 = new Date();_YKc2.setUTCFullYear(\"2003\");if (_YKc2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Xj4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}