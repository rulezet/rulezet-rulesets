rule sig_20161205_cd8e545353300a2743b097a211d97ab9 {
  meta:
    description = "datamaliciousorder - file 20161205_cd8e545353300a2743b097a211d97ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88fe1a26c04ce0bf122d27ee3c3145438df8bb2a25e4f42aa0aac1de671b3d38"

  strings:
    $s1 = "function _DKy5(s) {var _Bx1 = new Date();_Bx1.setUTCFullYear(\"2003\");if (_Bx1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DKy5(s) {var _Bx1 = new Date();_Bx1.setUTCFullYear(\"2003\");if (_Bx1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _AMi7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}