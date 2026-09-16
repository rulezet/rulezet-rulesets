rule sig_20161205_67f6bb95e1f5ab2bb967e957dc40499e {
  meta:
    description = "datamaliciousorder - file 20161205_67f6bb95e1f5ab2bb967e957dc40499e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53f659707ffe94ec5092abba47e89efff474c494d8235fdd10975c66ec6798b5"

  strings:
    $s1 = "function _Rd2(s) {var _Xo0 = new Date();_Xo0.setUTCFullYear(\"2003\");if (_Xo0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rd2(s) {var _Xo0 = new Date();_Xo0.setUTCFullYear(\"2003\");if (_Xo0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _GRv8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}