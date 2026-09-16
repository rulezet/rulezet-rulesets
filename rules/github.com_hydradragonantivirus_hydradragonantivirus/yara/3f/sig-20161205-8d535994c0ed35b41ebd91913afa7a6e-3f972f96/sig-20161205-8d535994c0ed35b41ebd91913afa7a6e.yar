rule sig_20161205_8d535994c0ed35b41ebd91913afa7a6e {
  meta:
    description = "datamaliciousorder - file 20161205_8d535994c0ed35b41ebd91913afa7a6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8497bcf72fe91a7edcc12e330287520aaa9fb3ea3ad7ad86a95bf566b7fb599"

  strings:
    $s1 = "function _Ib1(s) {var _MGl2 = new Date();_MGl2.setUTCFullYear(\"2003\");if (_MGl2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ib1(s) {var _MGl2 = new Date();_MGl2.setUTCFullYear(\"2003\");if (_MGl2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _LCp0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}