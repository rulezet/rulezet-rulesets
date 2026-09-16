rule sig_20161205_85615b44905b2cf222eb03d757e7d24c {
  meta:
    description = "datamaliciousorder - file 20161205_85615b44905b2cf222eb03d757e7d24c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7daa0dfb1f40b5b96e772780480c8ff77796f27594ce7632580fca021d9dd91a"

  strings:
    $s1 = "function _Lb6(s) {var _BOn7 = new Date();_BOn7.setUTCFullYear(\"2003\");if (_BOn7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Lb6(s) {var _BOn7 = new Date();_BOn7.setUTCFullYear(\"2003\");if (_BOn7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _IWj8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}