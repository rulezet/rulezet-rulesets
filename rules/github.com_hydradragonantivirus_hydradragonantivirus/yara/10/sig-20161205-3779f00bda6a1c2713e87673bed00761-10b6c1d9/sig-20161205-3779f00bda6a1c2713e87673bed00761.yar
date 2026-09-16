rule sig_20161205_3779f00bda6a1c2713e87673bed00761 {
  meta:
    description = "datamaliciousorder - file 20161205_3779f00bda6a1c2713e87673bed00761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a6eefc62353d2983d7d874c635a52ad95a9fe1182aab884b3f072d772eadd09"

  strings:
    $s1 = "function _OEo1(s) {var _Fw5 = new Date();_Fw5.setUTCFullYear(\"2003\");if (_Fw5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OEo1(s) {var _Fw5 = new Date();_Fw5.setUTCFullYear(\"2003\");if (_Fw5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _LAw8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}