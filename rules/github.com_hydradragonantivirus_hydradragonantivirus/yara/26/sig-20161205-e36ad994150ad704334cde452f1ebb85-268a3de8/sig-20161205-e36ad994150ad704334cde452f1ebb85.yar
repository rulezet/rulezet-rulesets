rule sig_20161205_e36ad994150ad704334cde452f1ebb85 {
  meta:
    description = "datamaliciousorder - file 20161205_e36ad994150ad704334cde452f1ebb85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b748f05897be66470668eed82c2013a8499a6f8798579bb8e929f16ba4f059dd"

  strings:
    $s1 = "function _LLi4(s) {var _MNk8 = new Date();_MNk8.setUTCFullYear(\"2003\");if (_MNk8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LLi4(s) {var _MNk8 = new Date();_MNk8.setUTCFullYear(\"2003\");if (_MNk8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ENu3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}