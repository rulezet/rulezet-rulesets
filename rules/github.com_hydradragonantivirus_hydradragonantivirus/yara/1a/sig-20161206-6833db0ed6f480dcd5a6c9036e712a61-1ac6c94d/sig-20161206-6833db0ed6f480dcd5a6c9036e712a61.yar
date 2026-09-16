rule sig_20161206_6833db0ed6f480dcd5a6c9036e712a61 {
  meta:
    description = "datamaliciousorder - file 20161206_6833db0ed6f480dcd5a6c9036e712a61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4d82f1bb7a71e7db525aeadf14da3dda7a03a207390da5ef1019458fe5f2e5a"

  strings:
    $s1 = "function _OCe4(s) {var _Ap8 = new Date();_Ap8.setUTCFullYear(\"2003\");if (_Ap8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OCe4(s) {var _Ap8 = new Date();_Ap8.setUTCFullYear(\"2003\");if (_Ap8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Xl8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}