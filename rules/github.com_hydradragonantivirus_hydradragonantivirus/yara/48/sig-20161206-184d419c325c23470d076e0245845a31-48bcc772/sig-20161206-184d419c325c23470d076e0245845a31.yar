rule sig_20161206_184d419c325c23470d076e0245845a31 {
  meta:
    description = "datamaliciousorder - file 20161206_184d419c325c23470d076e0245845a31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7e418fb502caca2b6c0cbfeb08cc649f1996a68542c87e259329e4583948786"

  strings:
    $s1 = "function _Oq2(s) {var _Ly0 = new Date();_Ly0.setUTCFullYear(\"2003\");if (_Ly0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Oq2(s) {var _Ly0 = new Date();_Ly0.setUTCFullYear(\"2003\");if (_Ly0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Nn6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}