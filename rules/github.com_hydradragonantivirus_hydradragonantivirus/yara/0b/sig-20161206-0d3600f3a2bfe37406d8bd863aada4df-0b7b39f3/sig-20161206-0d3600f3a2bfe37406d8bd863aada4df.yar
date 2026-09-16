rule sig_20161206_0d3600f3a2bfe37406d8bd863aada4df {
  meta:
    description = "datamaliciousorder - file 20161206_0d3600f3a2bfe37406d8bd863aada4df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26d96ead473a5c43a69e553010f691413c40b9c6ef45acdab499ba91114d5944"

  strings:
    $s1 = "function _ZPc2(s) {var _Jk5 = new Date();_Jk5.setUTCFullYear(\"2003\");if (_Jk5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZPc2(s) {var _Jk5 = new Date();_Jk5.setUTCFullYear(\"2003\");if (_Jk5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Jn7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}