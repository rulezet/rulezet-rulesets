rule sig_20161205_6e93dad6484dde6c52353c3e28382e67 {
  meta:
    description = "datamaliciousorder - file 20161205_6e93dad6484dde6c52353c3e28382e67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af8f99a032a8cb6bd5071f6418f6fd95e5616480ca2e349e2e7d770e0a6bd749"

  strings:
    $s1 = "function _Mf6(s) {var _Qb8 = new Date();_Qb8.setUTCFullYear(\"2003\");if (_Qb8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Mf6(s) {var _Qb8 = new Date();_Qb8.setUTCFullYear(\"2003\");if (_Qb8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Rv5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}