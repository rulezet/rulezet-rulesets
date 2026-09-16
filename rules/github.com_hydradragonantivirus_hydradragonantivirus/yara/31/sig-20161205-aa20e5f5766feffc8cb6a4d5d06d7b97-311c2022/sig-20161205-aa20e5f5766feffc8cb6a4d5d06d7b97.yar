rule sig_20161205_aa20e5f5766feffc8cb6a4d5d06d7b97 {
  meta:
    description = "datamaliciousorder - file 20161205_aa20e5f5766feffc8cb6a4d5d06d7b97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a37afdec22c12672d83b218ee528a3bcffdb382593f317eada92dad39edaac58"

  strings:
    $s1 = "function _De0(s) {var _Jj5 = new Date();_Jj5.setUTCFullYear(\"2003\");if (_Jj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _De0(s) {var _Jj5 = new Date();_Jj5.setUTCFullYear(\"2003\");if (_Jj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Dn0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}