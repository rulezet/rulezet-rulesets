rule sig_20161205_7cf33b9d23f12fc86d726af0894a238c {
  meta:
    description = "datamaliciousorder - file 20161205_7cf33b9d23f12fc86d726af0894a238c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "918e8eb44fd8fb35cae5cbd2d2d46e530e28212b7d6c615571262a908f4f7d32"

  strings:
    $s1 = "function _FBg3(s) {var _Kx4 = new Date();_Kx4.setUTCFullYear(\"2003\");if (_Kx4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FBg3(s) {var _Kx4 = new Date();_Kx4.setUTCFullYear(\"2003\");if (_Kx4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Tb0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}