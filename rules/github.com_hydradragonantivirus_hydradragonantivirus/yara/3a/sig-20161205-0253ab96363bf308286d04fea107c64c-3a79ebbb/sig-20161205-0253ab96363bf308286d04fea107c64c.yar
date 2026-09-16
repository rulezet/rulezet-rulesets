rule sig_20161205_0253ab96363bf308286d04fea107c64c {
  meta:
    description = "datamaliciousorder - file 20161205_0253ab96363bf308286d04fea107c64c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0f76e67b9e412ad7b1a4317b31f69421cdd80f365134fafaed3cafea1c16ff1"

  strings:
    $s1 = "function _JDd8(s) {var _SMv3 = new Date();_SMv3.setUTCFullYear(\"2003\");if (_SMv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JDd8(s) {var _SMv3 = new Date();_SMv3.setUTCFullYear(\"2003\");if (_SMv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _JUo1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}