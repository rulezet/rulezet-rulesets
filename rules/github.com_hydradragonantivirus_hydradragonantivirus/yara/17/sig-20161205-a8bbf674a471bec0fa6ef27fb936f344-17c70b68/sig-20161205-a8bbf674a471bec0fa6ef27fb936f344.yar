rule sig_20161205_a8bbf674a471bec0fa6ef27fb936f344 {
  meta:
    description = "datamaliciousorder - file 20161205_a8bbf674a471bec0fa6ef27fb936f344.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fa5a05dd746d1c570288f263dcc1f39ef5b0fbb6d0b990ae775ffcea76480dc"

  strings:
    $s1 = "function _Ux2(s) {var _Vr3 = new Date();_Vr3.setUTCFullYear(\"2003\");if (_Vr3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ux2(s) {var _Vr3 = new Date();_Vr3.setUTCFullYear(\"2003\");if (_Vr3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _KLs9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}