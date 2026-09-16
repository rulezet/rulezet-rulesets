rule sig_20161205_6aa5893aa5b752d36b8bd2193af4df6d {
  meta:
    description = "datamaliciousorder - file 20161205_6aa5893aa5b752d36b8bd2193af4df6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "505b2eb27a3b08127304dfb90a5da8dc04de3ce96d966ade3e5b030c0dab1bf9"

  strings:
    $s1 = "function _EOn3(s) {var _Un2 = new Date();_Un2.setUTCFullYear(\"2003\");if (_Un2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _EOn3(s) {var _Un2 = new Date();_Un2.setUTCFullYear(\"2003\");if (_Un2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Gr5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}