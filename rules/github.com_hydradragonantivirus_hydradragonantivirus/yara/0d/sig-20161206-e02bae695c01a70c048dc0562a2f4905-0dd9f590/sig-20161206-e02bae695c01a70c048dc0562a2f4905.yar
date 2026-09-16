rule sig_20161206_e02bae695c01a70c048dc0562a2f4905 {
  meta:
    description = "datamaliciousorder - file 20161206_e02bae695c01a70c048dc0562a2f4905.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f97367ccfa4d5cdb96474ff8068d2ee372baee12882529fa0b5490dbcdf8c4d7"

  strings:
    $s1 = "function _Qv0(s) {var _Jj7 = new Date();_Jj7.setUTCFullYear(\"2003\");if (_Jj7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qv0(s) {var _Jj7 = new Date();_Jj7.setUTCFullYear(\"2003\");if (_Jj7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Yu8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}