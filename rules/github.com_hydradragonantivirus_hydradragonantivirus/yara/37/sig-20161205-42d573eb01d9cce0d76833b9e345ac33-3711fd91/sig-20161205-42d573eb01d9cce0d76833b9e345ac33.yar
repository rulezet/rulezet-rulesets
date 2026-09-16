rule sig_20161205_42d573eb01d9cce0d76833b9e345ac33 {
  meta:
    description = "datamaliciousorder - file 20161205_42d573eb01d9cce0d76833b9e345ac33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74366f735903d390af04636b77a66f8373706f89a84afb3e2cd32be97d0c14db"

  strings:
    $s1 = "function _Ba5(s) {var _KEa3 = new Date();_KEa3.setUTCFullYear(\"2003\");if (_KEa3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ba5(s) {var _KEa3 = new Date();_KEa3.setUTCFullYear(\"2003\");if (_KEa3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Vr9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}