rule sig_20161205_ca6a0f438b927e4934086a2066fdb079 {
  meta:
    description = "datamaliciousorder - file 20161205_ca6a0f438b927e4934086a2066fdb079.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd9f452666cb7924633441ac9496bfd3dc8a65f0ad8dec3483a306850e0f7f3"

  strings:
    $s1 = "function _OMz7(s) {var _Ay8 = new Date();_Ay8.setUTCFullYear(\"2003\");if (_Ay8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OMz7(s) {var _Ay8 = new Date();_Ay8.setUTCFullYear(\"2003\");if (_Ay8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NTn9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}