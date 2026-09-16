rule sig_20161205_848822807abf224de31f3ecbc8aba572 {
  meta:
    description = "datamaliciousorder - file 20161205_848822807abf224de31f3ecbc8aba572.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef3c01fb24d244d46dabb00a61daac862fbaa79ee9def46a7e7ba9cd6299758c"

  strings:
    $s1 = "function _Ti1(s) {var _Jz9 = new Date();_Jz9.setUTCFullYear(\"2003\");if (_Jz9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ti1(s) {var _Jz9 = new Date();_Jz9.setUTCFullYear(\"2003\");if (_Jz9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XSa9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}