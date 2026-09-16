rule sig_20161205_e3db40cfd36b65b7d5cbc75601f67a2b {
  meta:
    description = "datamaliciousorder - file 20161205_e3db40cfd36b65b7d5cbc75601f67a2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b97036a83f6cb49a60208d65587a6676b4a047693681910b69acfccbb67e186c"

  strings:
    $s1 = "function _Cd4(s) {var _JWa9 = new Date();_JWa9.setUTCFullYear(\"2003\");if (_JWa9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Cd4(s) {var _JWa9 = new Date();_JWa9.setUTCFullYear(\"2003\");if (_JWa9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ij7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}