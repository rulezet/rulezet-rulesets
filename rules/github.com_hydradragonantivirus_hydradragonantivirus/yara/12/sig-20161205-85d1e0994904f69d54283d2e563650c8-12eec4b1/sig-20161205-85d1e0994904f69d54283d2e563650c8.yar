rule sig_20161205_85d1e0994904f69d54283d2e563650c8 {
  meta:
    description = "datamaliciousorder - file 20161205_85d1e0994904f69d54283d2e563650c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0b571863a6cb4a8fcd2a17df9bee5f563ac8bce1df9ba4b94914ef76ce572f3"

  strings:
    $s1 = "function _Bu1(s) {var _RTs6 = new Date();_RTs6.setUTCFullYear(\"2003\");if (_RTs6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bu1(s) {var _RTs6 = new Date();_RTs6.setUTCFullYear(\"2003\");if (_RTs6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _PZx6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}