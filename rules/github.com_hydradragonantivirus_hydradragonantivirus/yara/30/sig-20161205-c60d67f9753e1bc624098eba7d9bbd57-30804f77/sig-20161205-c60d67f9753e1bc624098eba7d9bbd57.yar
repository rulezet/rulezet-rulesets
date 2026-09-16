rule sig_20161205_c60d67f9753e1bc624098eba7d9bbd57 {
  meta:
    description = "datamaliciousorder - file 20161205_c60d67f9753e1bc624098eba7d9bbd57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6acbc54d973f1268a1b363181ac9631c2576fc715056e154bd7df377cf24c10"

  strings:
    $s1 = "function _Un9(s) {var _MOe2 = new Date();_MOe2.setUTCFullYear(\"2003\");if (_MOe2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Un9(s) {var _MOe2 = new Date();_MOe2.setUTCFullYear(\"2003\");if (_MOe2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _HNg9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}