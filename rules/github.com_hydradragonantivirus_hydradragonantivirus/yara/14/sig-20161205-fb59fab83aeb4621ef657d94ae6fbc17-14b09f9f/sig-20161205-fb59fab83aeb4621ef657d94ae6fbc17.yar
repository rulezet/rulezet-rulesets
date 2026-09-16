rule sig_20161205_fb59fab83aeb4621ef657d94ae6fbc17 {
  meta:
    description = "datamaliciousorder - file 20161205_fb59fab83aeb4621ef657d94ae6fbc17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4436a8b4c4da5c8e701863e2fcf3df9c7003f372b714162c041e4f2db2bd4954"

  strings:
    $s1 = "function _Fc0(s) {var _Qr1 = new Date();_Qr1.setUTCFullYear(\"2003\");if (_Qr1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fc0(s) {var _Qr1 = new Date();_Qr1.setUTCFullYear(\"2003\");if (_Qr1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HDu5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}