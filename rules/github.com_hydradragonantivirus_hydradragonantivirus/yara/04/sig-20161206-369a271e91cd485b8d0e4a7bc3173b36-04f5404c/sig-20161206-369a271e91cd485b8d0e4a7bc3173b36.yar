rule sig_20161206_369a271e91cd485b8d0e4a7bc3173b36 {
  meta:
    description = "datamaliciousorder - file 20161206_369a271e91cd485b8d0e4a7bc3173b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5794080924b1a31e4b3858816b7a95e980c38e6a0b15171a69a5da19e0665fe8"

  strings:
    $s1 = "function _BOa5(s) {var _Pp9 = new Date();_Pp9.setUTCFullYear(\"2003\");if (_Pp9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BOa5(s) {var _Pp9 = new Date();_Pp9.setUTCFullYear(\"2003\");if (_Pp9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vq9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}