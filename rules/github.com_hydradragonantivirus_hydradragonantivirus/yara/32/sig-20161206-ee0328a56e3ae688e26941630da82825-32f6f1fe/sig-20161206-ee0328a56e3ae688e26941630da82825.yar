rule sig_20161206_ee0328a56e3ae688e26941630da82825 {
  meta:
    description = "datamaliciousorder - file 20161206_ee0328a56e3ae688e26941630da82825.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95f9449bd921aa8cb05f6617a9526cf9a6536324985c33be6805f28cf62f424"

  strings:
    $s1 = "function _Is9(s) {var _Zy9 = new Date();_Zy9.setUTCFullYear(\"2003\");if (_Zy9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Is9(s) {var _Zy9 = new Date();_Zy9.setUTCFullYear(\"2003\");if (_Zy9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XBh3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}