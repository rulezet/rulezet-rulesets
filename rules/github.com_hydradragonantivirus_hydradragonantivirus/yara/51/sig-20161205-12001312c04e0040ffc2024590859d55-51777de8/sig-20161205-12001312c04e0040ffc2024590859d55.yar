rule sig_20161205_12001312c04e0040ffc2024590859d55 {
  meta:
    description = "datamaliciousorder - file 20161205_12001312c04e0040ffc2024590859d55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1ba2c17570d2dfd9cfe6370734370af5af28917f2e104959501f8c109fa9dbf"

  strings:
    $s1 = "function _THn5(s) {var _ISn2 = new Date();_ISn2.setUTCFullYear(\"2003\");if (_ISn2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _THn5(s) {var _ISn2 = new Date();_ISn2.setUTCFullYear(\"2003\");if (_ISn2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ub1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}