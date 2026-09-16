rule sig_20161205_9ccce67ed151b5395b4fbcd40cf7704b {
  meta:
    description = "datamaliciousorder - file 20161205_9ccce67ed151b5395b4fbcd40cf7704b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3a569344d967791d4b6b554a652751ed5cf468293902cc6ab4894fca3a4cc67"

  strings:
    $s1 = "function _IQf3(s) {var _St9 = new Date();_St9.setUTCFullYear(\"2003\");if (_St9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IQf3(s) {var _St9 = new Date();_St9.setUTCFullYear(\"2003\");if (_St9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Wm2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}