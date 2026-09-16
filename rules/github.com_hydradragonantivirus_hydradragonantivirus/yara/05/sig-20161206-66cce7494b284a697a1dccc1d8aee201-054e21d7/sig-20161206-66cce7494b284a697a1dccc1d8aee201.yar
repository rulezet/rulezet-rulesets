rule sig_20161206_66cce7494b284a697a1dccc1d8aee201 {
  meta:
    description = "datamaliciousorder - file 20161206_66cce7494b284a697a1dccc1d8aee201.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63ab37cfc19a6924dbc1d0ba254a525a35ce4774dad65df9481ddaf02c10548f"

  strings:
    $s1 = "function _Kg9(s) {var _YYe7 = new Date();_YYe7.setUTCFullYear(\"2003\");if (_YYe7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kg9(s) {var _YYe7 = new Date();_YYe7.setUTCFullYear(\"2003\");if (_YYe7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TFk8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}