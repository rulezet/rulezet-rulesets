rule sig_20161205_39f0d3b66532eebcc08fed6becea4881 {
  meta:
    description = "datamaliciousorder - file 20161205_39f0d3b66532eebcc08fed6becea4881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca8d0e969ea71cc70442009e391ec275d67acdca3be295567d4c3469b44e83c"

  strings:
    $s1 = "function _Zc8(s) {var _Za4 = new Date();_Za4.setUTCFullYear(\"2003\");if (_Za4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zc8(s) {var _Za4 = new Date();_Za4.setUTCFullYear(\"2003\");if (_Za4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Jd5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}