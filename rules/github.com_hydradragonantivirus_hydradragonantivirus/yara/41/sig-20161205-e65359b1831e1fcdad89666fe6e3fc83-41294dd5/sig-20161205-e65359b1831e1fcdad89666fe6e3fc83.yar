rule sig_20161205_e65359b1831e1fcdad89666fe6e3fc83 {
  meta:
    description = "datamaliciousorder - file 20161205_e65359b1831e1fcdad89666fe6e3fc83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc23c2cf2fcd731dbf1d77e01bdc6658c364fa31a56d807396d010db4fe3eb38"

  strings:
    $s1 = "function _Re4(s) {var _Vq3 = new Date();_Vq3.setUTCFullYear(\"2003\");if (_Vq3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Re4(s) {var _Vq3 = new Date();_Vq3.setUTCFullYear(\"2003\");if (_Vq3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _VTj3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}