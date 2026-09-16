rule sig_20161205_4c8789be667d8358a82d52a76af78d7c {
  meta:
    description = "datamaliciousorder - file 20161205_4c8789be667d8358a82d52a76af78d7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee349e30e407972475f8b4911547cbf480c2d4e7346ae2033682302fefde012a"

  strings:
    $s1 = "function _Xd2(s) {var _Sq4 = new Date();_Sq4.setUTCFullYear(\"2003\");if (_Sq4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xd2(s) {var _Sq4 = new Date();_Sq4.setUTCFullYear(\"2003\");if (_Sq4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _WKc8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}