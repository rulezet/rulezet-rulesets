rule sig_20161206_e0fc100a77639fe29e4e768e458f2e47 {
  meta:
    description = "datamaliciousorder - file 20161206_e0fc100a77639fe29e4e768e458f2e47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a64092bb79564af153b027189ff0e7b96dbbebe82d252675fd759f2d1bc70857"

  strings:
    $s1 = "function _Ui0(s) {var _EHg3 = new Date();_EHg3.setUTCFullYear(\"2003\");if (_EHg3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ui0(s) {var _EHg3 = new Date();_EHg3.setUTCFullYear(\"2003\");if (_EHg3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _NWo7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}