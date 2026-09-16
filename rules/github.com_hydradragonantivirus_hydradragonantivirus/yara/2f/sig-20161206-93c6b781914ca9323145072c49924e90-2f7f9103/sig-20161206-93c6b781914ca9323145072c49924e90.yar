rule sig_20161206_93c6b781914ca9323145072c49924e90 {
  meta:
    description = "datamaliciousorder - file 20161206_93c6b781914ca9323145072c49924e90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "399f2bc0842b41358d53b2192c5586ab526ac7c078f100fee03b5099501a80f1"

  strings:
    $s1 = "function _NLm2(s) {var _YIe5 = new Date();_YIe5.setUTCFullYear(\"2003\");if (_YIe5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NLm2(s) {var _YIe5 = new Date();_YIe5.setUTCFullYear(\"2003\");if (_YIe5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Eo3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}