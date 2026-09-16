rule sig_20161205_920335a4426b1f2e2f28dc502863414f {
  meta:
    description = "datamaliciousorder - file 20161205_920335a4426b1f2e2f28dc502863414f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "341e7b0377d6fd7b8e5d1afb5d559db8eeb2cae1ca49811bd5b964fab871aebe"

  strings:
    $s1 = "function _BKr2(s) {var _ZHq6 = new Date();_ZHq6.setUTCFullYear(\"2003\");if (_ZHq6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BKr2(s) {var _ZHq6 = new Date();_ZHq6.setUTCFullYear(\"2003\");if (_ZHq6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZJk8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}