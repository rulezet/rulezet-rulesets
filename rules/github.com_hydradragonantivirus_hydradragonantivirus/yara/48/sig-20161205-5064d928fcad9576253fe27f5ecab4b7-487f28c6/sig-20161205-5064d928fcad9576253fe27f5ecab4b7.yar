rule sig_20161205_5064d928fcad9576253fe27f5ecab4b7 {
  meta:
    description = "datamaliciousorder - file 20161205_5064d928fcad9576253fe27f5ecab4b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "600d2d441e007492f45e35aaa1bf1c60b30904ca85b3f51aed4d25dfb78cda69"

  strings:
    $s1 = "function _Oz5(s) {var _Vy6 = new Date();_Vy6.setUTCFullYear(\"2003\");if (_Vy6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Oz5(s) {var _Vy6 = new Date();_Vy6.setUTCFullYear(\"2003\");if (_Vy6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ADs7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}