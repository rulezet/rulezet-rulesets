rule sig_20161205_4d08857231f56912576c7846fada0e1a {
  meta:
    description = "datamaliciousorder - file 20161205_4d08857231f56912576c7846fada0e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83dde2edee348414a4ada39317f0d20383a1729840f874193221884e5d0b0df0"

  strings:
    $s1 = "function _Kb4(s) {var _Ff6 = new Date();_Ff6.setUTCFullYear(\"2003\");if (_Ff6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Kb4(s) {var _Ff6 = new Date();_Ff6.setUTCFullYear(\"2003\");if (_Ff6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _LOs8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}