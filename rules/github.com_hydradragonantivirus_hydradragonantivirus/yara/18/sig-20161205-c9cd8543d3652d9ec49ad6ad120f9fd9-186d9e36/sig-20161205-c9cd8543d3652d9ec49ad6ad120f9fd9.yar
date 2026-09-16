rule sig_20161205_c9cd8543d3652d9ec49ad6ad120f9fd9 {
  meta:
    description = "datamaliciousorder - file 20161205_c9cd8543d3652d9ec49ad6ad120f9fd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b12ad842adcf05855bd010d6f66120e186f7edab5d34d6390237f330f7784984"

  strings:
    $s1 = "function _Jg8(s) {var _YUd2 = new Date();_YUd2.setUTCFullYear(\"2003\");if (_YUd2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Jg8(s) {var _YUd2 = new Date();_YUd2.setUTCFullYear(\"2003\");if (_YUd2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Cy8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}