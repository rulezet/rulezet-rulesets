rule sig_20161205_49c1293e3815f70a1b9d62478a3a7eab {
  meta:
    description = "datamaliciousorder - file 20161205_49c1293e3815f70a1b9d62478a3a7eab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81f4580751ab7ea52b1485132cf31038cfbe7af6158ef64a214a3ecd35b3c7cb"

  strings:
    $s1 = "function _Yi1(s) {var _Bs8 = new Date();_Bs8.setUTCFullYear(\"2003\");if (_Bs8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yi1(s) {var _Bs8 = new Date();_Bs8.setUTCFullYear(\"2003\");if (_Bs8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Cw6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}