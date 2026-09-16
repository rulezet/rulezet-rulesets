rule sig_20161205_e755d0582073557887a06b2ba18144b3 {
  meta:
    description = "datamaliciousorder - file 20161205_e755d0582073557887a06b2ba18144b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30938ed60a73c52fedbe5d145cd329f98b2e309f5acefe7cf34ad88b8f4f83b6"

  strings:
    $s1 = "function _OIy7(s) {var _FEd6 = new Date();_FEd6.setUTCFullYear(\"2003\");if (_FEd6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _OIy7(s) {var _FEd6 = new Date();_FEd6.setUTCFullYear(\"2003\");if (_FEd6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _MAh8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}