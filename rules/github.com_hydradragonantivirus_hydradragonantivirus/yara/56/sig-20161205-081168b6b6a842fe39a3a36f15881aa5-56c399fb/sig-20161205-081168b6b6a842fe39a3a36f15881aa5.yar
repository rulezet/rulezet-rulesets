rule sig_20161205_081168b6b6a842fe39a3a36f15881aa5 {
  meta:
    description = "datamaliciousorder - file 20161205_081168b6b6a842fe39a3a36f15881aa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681cc688b8a6c67cb484f1c6e48d0d3d7cfecd3aedbeadeeb7a02544e7d021f3"

  strings:
    $s1 = "function _Ca7(s) {var _AFz5 = new Date();_AFz5.setUTCFullYear(\"2003\");if (_AFz5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ca7(s) {var _AFz5 = new Date();_AFz5.setUTCFullYear(\"2003\");if (_AFz5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _JNo9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}