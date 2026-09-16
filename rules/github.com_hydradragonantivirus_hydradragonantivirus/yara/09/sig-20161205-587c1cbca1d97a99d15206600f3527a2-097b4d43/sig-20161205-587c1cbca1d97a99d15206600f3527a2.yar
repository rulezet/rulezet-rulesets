rule sig_20161205_587c1cbca1d97a99d15206600f3527a2 {
  meta:
    description = "datamaliciousorder - file 20161205_587c1cbca1d97a99d15206600f3527a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "009a27e446e51cdfa28887765d02de2fa213a3c658a0e76b3954d1306181d873"

  strings:
    $s1 = "function _Ct6(s) {var _NJd6 = new Date();_NJd6.setUTCFullYear(\"2003\");if (_NJd6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ct6(s) {var _NJd6 = new Date();_NJd6.setUTCFullYear(\"2003\");if (_NJd6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Bm0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}