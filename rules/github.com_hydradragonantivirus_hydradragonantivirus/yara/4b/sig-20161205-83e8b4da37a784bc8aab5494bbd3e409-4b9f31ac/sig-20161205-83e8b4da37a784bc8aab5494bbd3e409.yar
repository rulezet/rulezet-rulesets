rule sig_20161205_83e8b4da37a784bc8aab5494bbd3e409 {
  meta:
    description = "datamaliciousorder - file 20161205_83e8b4da37a784bc8aab5494bbd3e409.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf225a9dac6f30b41b91d7652ce806470364bccfaf00aacd738ed30d94605965"

  strings:
    $s1 = "function _Ck6(s) {var _Kx7 = new Date();_Kx7.setUTCFullYear(\"2003\");if (_Kx7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ck6(s) {var _Kx7 = new Date();_Kx7.setUTCFullYear(\"2003\");if (_Kx7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Go0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}