rule sig_20161205_806ab28af4b74a0d1233916ad0442024 {
  meta:
    description = "datamaliciousorder - file 20161205_806ab28af4b74a0d1233916ad0442024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c9d4e5a4b1294b44816e3660080abd60acd1593329c673bbf52965b78011c40"

  strings:
    $s1 = "function _Nr1(s) {var _YDe7 = new Date();_YDe7.setUTCFullYear(\"2003\");if (_YDe7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nr1(s) {var _YDe7 = new Date();_YDe7.setUTCFullYear(\"2003\");if (_YDe7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Qu7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}