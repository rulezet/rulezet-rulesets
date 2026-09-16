rule sig_20161206_b8227279b77db34e9ec4c25c8f301a2b {
  meta:
    description = "datamaliciousorder - file 20161206_b8227279b77db34e9ec4c25c8f301a2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa156c544e71c518953b37a64f086cdddd2e9ac9b8bcb9e7d3533d7bec418923"

  strings:
    $s1 = "function _QFd6(s) {var _Uc5 = new Date();_Uc5.setUTCFullYear(\"2003\");if (_Uc5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QFd6(s) {var _Uc5 = new Date();_Uc5.setUTCFullYear(\"2003\");if (_Uc5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _LPq3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}