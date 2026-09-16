rule sig_20161205_4eb87eebc9a3da220ba5c169d9c1f9aa {
  meta:
    description = "datamaliciousorder - file 20161205_4eb87eebc9a3da220ba5c169d9c1f9aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89cce3b46b731d72e0f64173b3ed5df7fdb2d334651e659003b99e56d37045df"

  strings:
    $s1 = "function _EEi2(s) {var _TZb0 = new Date();_TZb0.setUTCFullYear(\"2003\");if (_TZb0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EEi2(s) {var _TZb0 = new Date();_TZb0.setUTCFullYear(\"2003\");if (_TZb0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Iu0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}