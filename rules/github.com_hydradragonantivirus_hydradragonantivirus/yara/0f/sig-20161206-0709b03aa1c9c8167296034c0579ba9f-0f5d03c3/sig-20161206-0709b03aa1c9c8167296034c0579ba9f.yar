rule sig_20161206_0709b03aa1c9c8167296034c0579ba9f {
  meta:
    description = "datamaliciousorder - file 20161206_0709b03aa1c9c8167296034c0579ba9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f392eaa282cb9876487aa140827fcdf2ac78703a5b50209de0a2a2d73c0fb1ae"

  strings:
    $s1 = "function _UOv0(s) {var _Bm5 = new Date();_Bm5.setUTCFullYear(\"2003\");if (_Bm5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UOv0(s) {var _Bm5 = new Date();_Bm5.setUTCFullYear(\"2003\");if (_Bm5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _SSk9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}