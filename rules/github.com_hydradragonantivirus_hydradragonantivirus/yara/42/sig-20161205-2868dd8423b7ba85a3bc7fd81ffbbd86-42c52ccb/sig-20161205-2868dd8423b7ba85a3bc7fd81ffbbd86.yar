rule sig_20161205_2868dd8423b7ba85a3bc7fd81ffbbd86 {
  meta:
    description = "datamaliciousorder - file 20161205_2868dd8423b7ba85a3bc7fd81ffbbd86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da0bee5709cf8e1d13b70c13a05ac4c79bf7491efbe98c335cf4fe13bf891bc0"

  strings:
    $s1 = "function _Kh7(s) {var _GMw9 = new Date();_GMw9.setUTCFullYear(\"2003\");if (_GMw9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kh7(s) {var _GMw9 = new Date();_GMw9.setUTCFullYear(\"2003\");if (_GMw9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Lk5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}