rule sig_20161205_3324defa52da3953cb626e7b8e1c77a5 {
  meta:
    description = "datamaliciousorder - file 20161205_3324defa52da3953cb626e7b8e1c77a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3686981070233abbc04e626dbab5ae0464de08c6c39bd02762d8d9aab347b73d"

  strings:
    $s1 = "function _ZVo9(s) {var _Es2 = new Date();_Es2.setUTCFullYear(\"2003\");if (_Es2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZVo9(s) {var _Es2 = new Date();_Es2.setUTCFullYear(\"2003\");if (_Es2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ax2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}