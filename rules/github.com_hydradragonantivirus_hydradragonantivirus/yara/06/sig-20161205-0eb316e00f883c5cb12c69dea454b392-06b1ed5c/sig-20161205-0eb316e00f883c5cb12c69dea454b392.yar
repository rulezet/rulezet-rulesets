rule sig_20161205_0eb316e00f883c5cb12c69dea454b392 {
  meta:
    description = "datamaliciousorder - file 20161205_0eb316e00f883c5cb12c69dea454b392.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf4be837030bec63c4a32e3c38e7c4836672254d6d79dfb678383a3d15c38dd5"

  strings:
    $s1 = "function _ONb6(s) {var _Dk2 = new Date();_Dk2.setUTCFullYear(\"2003\");if (_Dk2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ONb6(s) {var _Dk2 = new Date();_Dk2.setUTCFullYear(\"2003\");if (_Dk2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Mj5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}