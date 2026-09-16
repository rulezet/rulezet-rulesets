rule sig_20161205_9817f5ea8a1bb38f7eb713bf01ef2c55 {
  meta:
    description = "datamaliciousorder - file 20161205_9817f5ea8a1bb38f7eb713bf01ef2c55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "549c05585d8888cb4737d9ebc7936994c927057fe201a02865967fb5f275b697"

  strings:
    $s1 = "function _LUz1(s) {var _Gm5 = new Date();_Gm5.setUTCFullYear(\"2003\");if (_Gm5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LUz1(s) {var _Gm5 = new Date();_Gm5.setUTCFullYear(\"2003\");if (_Gm5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NXk0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}