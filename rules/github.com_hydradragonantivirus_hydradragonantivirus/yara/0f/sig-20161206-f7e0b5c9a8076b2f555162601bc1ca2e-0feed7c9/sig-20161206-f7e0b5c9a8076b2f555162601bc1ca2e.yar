rule sig_20161206_f7e0b5c9a8076b2f555162601bc1ca2e {
  meta:
    description = "datamaliciousorder - file 20161206_f7e0b5c9a8076b2f555162601bc1ca2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9345eca0282a14f7e5fecd650d2aaeade4d541eb1e63b1a8022a378ec426cf5b"

  strings:
    $s1 = "function _QXp4(s) {var _XEv3 = new Date();_XEv3.setUTCFullYear(\"2003\");if (_XEv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QXp4(s) {var _XEv3 = new Date();_XEv3.setUTCFullYear(\"2003\");if (_XEv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Td9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}