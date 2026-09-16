rule sig_20161205_ea6422bf88195013135c50e592a4e0ef {
  meta:
    description = "datamaliciousorder - file 20161205_ea6422bf88195013135c50e592a4e0ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b93d6579157ea0edb9325b48904f207ae6e5ac6d210c5a5a7cb14e2af738f33c"

  strings:
    $s1 = "function _GBj3(s) {var _PLs9 = new Date();_PLs9.setUTCFullYear(\"2003\");if (_PLs9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GBj3(s) {var _PLs9 = new Date();_PLs9.setUTCFullYear(\"2003\");if (_PLs9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _OQe2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}