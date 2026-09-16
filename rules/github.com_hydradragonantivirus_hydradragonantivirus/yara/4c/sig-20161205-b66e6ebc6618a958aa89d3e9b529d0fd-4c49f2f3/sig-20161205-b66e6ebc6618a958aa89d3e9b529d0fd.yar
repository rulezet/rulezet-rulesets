rule sig_20161205_b66e6ebc6618a958aa89d3e9b529d0fd {
  meta:
    description = "datamaliciousorder - file 20161205_b66e6ebc6618a958aa89d3e9b529d0fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8ded0540be5edaf006069d70041416f8627f4e216583451951dfcdd46322f42"

  strings:
    $s1 = "function _XVx6(s) {var _YBd7 = new Date();_YBd7.setUTCFullYear(\"2003\");if (_YBd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XVx6(s) {var _YBd7 = new Date();_YBd7.setUTCFullYear(\"2003\");if (_YBd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _MUz4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}