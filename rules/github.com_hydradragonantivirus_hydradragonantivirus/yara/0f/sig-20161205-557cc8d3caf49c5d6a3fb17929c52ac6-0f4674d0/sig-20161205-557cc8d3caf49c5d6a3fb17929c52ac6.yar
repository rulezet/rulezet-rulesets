rule sig_20161205_557cc8d3caf49c5d6a3fb17929c52ac6 {
  meta:
    description = "datamaliciousorder - file 20161205_557cc8d3caf49c5d6a3fb17929c52ac6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d35cfb049f2b62b8adcd5c92a0ab33416d823c83ad9ccb90ce6d3ec74c1e4f8"

  strings:
    $s1 = "function _Iw1(s) {var _Jp5 = new Date();_Jp5.setUTCFullYear(\"2003\");if (_Jp5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Iw1(s) {var _Jp5 = new Date();_Jp5.setUTCFullYear(\"2003\");if (_Jp5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _RNj5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}