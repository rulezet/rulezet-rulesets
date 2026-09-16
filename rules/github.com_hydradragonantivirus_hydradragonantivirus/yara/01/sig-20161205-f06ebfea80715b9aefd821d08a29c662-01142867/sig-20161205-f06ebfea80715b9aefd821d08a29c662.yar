rule sig_20161205_f06ebfea80715b9aefd821d08a29c662 {
  meta:
    description = "datamaliciousorder - file 20161205_f06ebfea80715b9aefd821d08a29c662.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "496ad54d8287aa40d0b38add15d5bb68cc49ee0c1f87199f3b62d90a0000b90e"

  strings:
    $s1 = "function _Uf2(s) {var _Sh3 = new Date();_Sh3.setUTCFullYear(\"2003\");if (_Sh3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uf2(s) {var _Sh3 = new Date();_Sh3.setUTCFullYear(\"2003\");if (_Sh3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Kq8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}