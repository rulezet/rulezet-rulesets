rule sig_20161205_435694296d3ea3d35edef73b45a66244 {
  meta:
    description = "datamaliciousorder - file 20161205_435694296d3ea3d35edef73b45a66244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82d61cd1cf329b82cb03447eddf47a0775daeef0ffc34a1f01d2e490edec41a1"

  strings:
    $s1 = "function _Kd3(s) {var _Rd9 = new Date();_Rd9.setUTCFullYear(\"2003\");if (_Rd9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Kd3(s) {var _Rd9 = new Date();_Rd9.setUTCFullYear(\"2003\");if (_Rd9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _UYp1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}