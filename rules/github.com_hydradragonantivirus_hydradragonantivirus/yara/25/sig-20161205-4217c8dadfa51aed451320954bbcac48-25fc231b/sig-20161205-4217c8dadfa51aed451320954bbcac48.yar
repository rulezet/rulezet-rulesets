rule sig_20161205_4217c8dadfa51aed451320954bbcac48 {
  meta:
    description = "datamaliciousorder - file 20161205_4217c8dadfa51aed451320954bbcac48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e99878b278ff2b93aed2551ba6d5dc901d4ea8b5e877e47b02c5ae13c2028ecb"

  strings:
    $s1 = "function _Mf2(s) {var _RKt2 = new Date();_RKt2.setUTCFullYear(\"2003\");if (_RKt2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Mf2(s) {var _RKt2 = new Date();_RKt2.setUTCFullYear(\"2003\");if (_RKt2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ya5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}