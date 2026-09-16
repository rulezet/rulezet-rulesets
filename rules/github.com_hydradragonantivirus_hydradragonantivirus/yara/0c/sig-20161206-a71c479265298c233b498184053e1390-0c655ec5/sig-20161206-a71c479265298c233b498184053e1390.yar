rule sig_20161206_a71c479265298c233b498184053e1390 {
  meta:
    description = "datamaliciousorder - file 20161206_a71c479265298c233b498184053e1390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15fc47e5025e1f75728b2bde983d4aee225c0cf179ea4e914c93c38f54e72074"

  strings:
    $s1 = "function _SNn8(s) {var _Zv8 = new Date();_Zv8.setUTCFullYear(\"2003\");if (_Zv8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SNn8(s) {var _Zv8 = new Date();_Zv8.setUTCFullYear(\"2003\");if (_Zv8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _HSt8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}