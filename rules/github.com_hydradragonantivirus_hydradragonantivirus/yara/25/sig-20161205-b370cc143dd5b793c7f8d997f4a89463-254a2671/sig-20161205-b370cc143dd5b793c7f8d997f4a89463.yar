rule sig_20161205_b370cc143dd5b793c7f8d997f4a89463 {
  meta:
    description = "datamaliciousorder - file 20161205_b370cc143dd5b793c7f8d997f4a89463.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0831e81585cc17bd3829a4c090ecd1a20f0e62a85c3fbbb046a456beb4999b6f"

  strings:
    $s1 = "function _KIt1(s) {var _Si9 = new Date();_Si9.setUTCFullYear(\"2003\");if (_Si9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KIt1(s) {var _Si9 = new Date();_Si9.setUTCFullYear(\"2003\");if (_Si9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ja2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}