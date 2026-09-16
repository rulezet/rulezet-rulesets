rule sig_20161205_c5321800170889c07f48e2d985298b6b {
  meta:
    description = "datamaliciousorder - file 20161205_c5321800170889c07f48e2d985298b6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de0f163db143dab795cdc0e6cd9fd14423eec86ca698aec25b2abe12edd1c5f6"

  strings:
    $s1 = "function _Wc2(s) {var _Lp3 = new Date();_Lp3.setUTCFullYear(\"2003\");if (_Lp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wc2(s) {var _Lp3 = new Date();_Lp3.setUTCFullYear(\"2003\");if (_Lp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Br0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}