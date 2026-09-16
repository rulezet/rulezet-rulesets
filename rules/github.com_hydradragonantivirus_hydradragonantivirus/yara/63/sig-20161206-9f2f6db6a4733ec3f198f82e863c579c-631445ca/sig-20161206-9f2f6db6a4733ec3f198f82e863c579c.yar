rule sig_20161206_9f2f6db6a4733ec3f198f82e863c579c {
  meta:
    description = "datamaliciousorder - file 20161206_9f2f6db6a4733ec3f198f82e863c579c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "005b38a22b30800b2cd5dbf424a26c1312ea5d819cf6adc94023381309b958c5"

  strings:
    $s1 = "function _So9(s) {var _Ht3 = new Date();_Ht3.setUTCFullYear(\"2003\");if (_Ht3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _So9(s) {var _Ht3 = new Date();_Ht3.setUTCFullYear(\"2003\");if (_Ht3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _GSf6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}