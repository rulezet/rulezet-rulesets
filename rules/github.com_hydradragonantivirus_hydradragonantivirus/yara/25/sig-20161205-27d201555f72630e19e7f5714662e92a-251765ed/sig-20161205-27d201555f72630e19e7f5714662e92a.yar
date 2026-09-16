rule sig_20161205_27d201555f72630e19e7f5714662e92a {
  meta:
    description = "datamaliciousorder - file 20161205_27d201555f72630e19e7f5714662e92a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a037c45143915fce3aeae2c28121d95f1495ebbd621d0661233f659463837d4"

  strings:
    $s1 = "function _RDd2(s) {var _KQd7 = new Date();_KQd7.setUTCFullYear(\"2003\");if (_KQd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _RDd2(s) {var _KQd7 = new Date();_KQd7.setUTCFullYear(\"2003\");if (_KQd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _PCu4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}