rule sig_20161205_828a6e8ff9c310c7f19901b42543861b {
  meta:
    description = "datamaliciousorder - file 20161205_828a6e8ff9c310c7f19901b42543861b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a29ca783bc36bd9b6475e0d5c38a1e23f63023f27f9e1e2d2d38d6c1db82e3a"

  strings:
    $s1 = "function _QWc3(s) {var _TJd5 = new Date();_TJd5.setUTCFullYear(\"2003\");if (_TJd5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QWc3(s) {var _TJd5 = new Date();_TJd5.setUTCFullYear(\"2003\");if (_TJd5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Gd8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}