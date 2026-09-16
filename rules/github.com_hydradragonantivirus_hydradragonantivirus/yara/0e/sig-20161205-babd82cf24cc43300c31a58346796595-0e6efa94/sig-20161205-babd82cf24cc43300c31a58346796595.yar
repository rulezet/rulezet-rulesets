rule sig_20161205_babd82cf24cc43300c31a58346796595 {
  meta:
    description = "datamaliciousorder - file 20161205_babd82cf24cc43300c31a58346796595.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810d7ec212124bd27da2d20614bd549f1ff5c3bf83224f4c3ffd2db327948f5"

  strings:
    $s1 = "function _JWq3(s) {var _KIg6 = new Date();_KIg6.setUTCFullYear(\"2003\");if (_KIg6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JWq3(s) {var _KIg6 = new Date();_KIg6.setUTCFullYear(\"2003\");if (_KIg6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Gc5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}