rule sig_20161206_b41d6cd2ab812a5e44a6595fe2b0fc84 {
  meta:
    description = "datamaliciousorder - file 20161206_b41d6cd2ab812a5e44a6595fe2b0fc84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc7c5735cf2f1a6f3bad6871f90a3f79805a34aa5e7f706a4290767bf1d043de"

  strings:
    $s1 = "function _AJh2(s) {var _IEm2 = new Date();_IEm2.setUTCFullYear(\"2003\");if (_IEm2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _AJh2(s) {var _IEm2 = new Date();_IEm2.setUTCFullYear(\"2003\");if (_IEm2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Uf3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}