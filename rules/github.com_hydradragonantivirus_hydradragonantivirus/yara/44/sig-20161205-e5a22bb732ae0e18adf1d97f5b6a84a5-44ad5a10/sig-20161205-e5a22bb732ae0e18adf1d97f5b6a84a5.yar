rule sig_20161205_e5a22bb732ae0e18adf1d97f5b6a84a5 {
  meta:
    description = "datamaliciousorder - file 20161205_e5a22bb732ae0e18adf1d97f5b6a84a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ccbc4424ddf135bb39d2ab96dc3fbdf1eedaddc65c9ead6b423eb17179ee1bc"

  strings:
    $s1 = "function _Pt5(s) {var _TNx1 = new Date();_TNx1.setUTCFullYear(\"2003\");if (_TNx1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Pt5(s) {var _TNx1 = new Date();_TNx1.setUTCFullYear(\"2003\");if (_TNx1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _GPo0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}