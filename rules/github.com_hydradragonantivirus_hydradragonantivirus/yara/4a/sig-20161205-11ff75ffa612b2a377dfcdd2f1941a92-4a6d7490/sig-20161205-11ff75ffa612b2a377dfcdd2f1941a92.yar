rule sig_20161205_11ff75ffa612b2a377dfcdd2f1941a92 {
  meta:
    description = "datamaliciousorder - file 20161205_11ff75ffa612b2a377dfcdd2f1941a92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30cd9ba0230ff43e23ca31fa85cb142bce9ac60227866d6631cf5dab8ea298a6"

  strings:
    $s1 = "function _SJf8(s) {var _YGt1 = new Date();_YGt1.setUTCFullYear(\"2003\");if (_YGt1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SJf8(s) {var _YGt1 = new Date();_YGt1.setUTCFullYear(\"2003\");if (_YGt1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Dt3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}