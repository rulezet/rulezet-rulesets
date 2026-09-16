rule sig_20161205_fa17fe756a328585d69b496542ae04fe {
  meta:
    description = "datamaliciousorder - file 20161205_fa17fe756a328585d69b496542ae04fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbcafbefb6213df4a6af043cc12d3375f494bb534eba7f0c2af273d85e167607"

  strings:
    $s1 = "function _Qd1(s) {var _Cw5 = new Date();_Cw5.setUTCFullYear(\"2003\");if (_Cw5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qd1(s) {var _Cw5 = new Date();_Cw5.setUTCFullYear(\"2003\");if (_Cw5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Gb0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}