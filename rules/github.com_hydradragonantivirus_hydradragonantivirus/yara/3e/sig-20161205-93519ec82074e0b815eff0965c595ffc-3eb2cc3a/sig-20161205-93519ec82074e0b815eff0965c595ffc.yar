rule sig_20161205_93519ec82074e0b815eff0965c595ffc {
  meta:
    description = "datamaliciousorder - file 20161205_93519ec82074e0b815eff0965c595ffc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ab1f3ec861f270dc26ab4afa3989d4f842373412cdbb87935f1d0af5bda8d26"

  strings:
    $s1 = "function _Pg2(s) {var _Gk8 = new Date();_Gk8.setUTCFullYear(\"2003\");if (_Gk8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pg2(s) {var _Gk8 = new Date();_Gk8.setUTCFullYear(\"2003\");if (_Gk8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _NAq7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}