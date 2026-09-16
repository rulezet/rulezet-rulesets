rule sig_20161206_fc8d4ba1f6bc4682f8143a229c24dc37 {
  meta:
    description = "datamaliciousorder - file 20161206_fc8d4ba1f6bc4682f8143a229c24dc37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "501768318cc523b11925f59bf845d74228d8472ab690cb74a2ac96e8a80b40f2"

  strings:
    $s1 = "function _IPl4(s) {var _Zd1 = new Date();_Zd1.setUTCFullYear(\"2003\");if (_Zd1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IPl4(s) {var _Zd1 = new Date();_Zd1.setUTCFullYear(\"2003\");if (_Zd1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Sz3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}