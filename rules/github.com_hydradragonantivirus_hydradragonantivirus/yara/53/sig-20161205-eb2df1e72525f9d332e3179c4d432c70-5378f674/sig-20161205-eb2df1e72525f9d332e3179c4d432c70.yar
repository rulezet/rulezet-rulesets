rule sig_20161205_eb2df1e72525f9d332e3179c4d432c70 {
  meta:
    description = "datamaliciousorder - file 20161205_eb2df1e72525f9d332e3179c4d432c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0881cd733dd584863daaf87341e4d0c38815a5aa62a9dc7f2608af2a3f1dc3e8"

  strings:
    $s1 = "function _EGe1(s) {var _ZBm5 = new Date();_ZBm5.setUTCFullYear(\"2003\");if (_ZBm5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EGe1(s) {var _ZBm5 = new Date();_ZBm5.setUTCFullYear(\"2003\");if (_ZBm5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _RMa8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}