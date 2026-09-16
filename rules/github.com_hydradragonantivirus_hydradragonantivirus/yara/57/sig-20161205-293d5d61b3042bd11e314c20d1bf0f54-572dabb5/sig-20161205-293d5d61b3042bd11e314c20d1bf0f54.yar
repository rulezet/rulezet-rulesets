rule sig_20161205_293d5d61b3042bd11e314c20d1bf0f54 {
  meta:
    description = "datamaliciousorder - file 20161205_293d5d61b3042bd11e314c20d1bf0f54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6808e3bff8d7fbbd45f394fe72979c39f1fec60067bf64bdd224cecd12126083"

  strings:
    $s1 = "function _LMj4(s) {var _Xe5 = new Date();_Xe5.setUTCFullYear(\"2003\");if (_Xe5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LMj4(s) {var _Xe5 = new Date();_Xe5.setUTCFullYear(\"2003\");if (_Xe5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Hl3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}