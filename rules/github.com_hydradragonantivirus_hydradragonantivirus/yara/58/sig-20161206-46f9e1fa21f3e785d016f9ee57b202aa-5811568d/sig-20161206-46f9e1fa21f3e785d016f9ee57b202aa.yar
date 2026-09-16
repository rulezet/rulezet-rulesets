rule sig_20161206_46f9e1fa21f3e785d016f9ee57b202aa {
  meta:
    description = "datamaliciousorder - file 20161206_46f9e1fa21f3e785d016f9ee57b202aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65f63611204dc2e09f75cc5fde2437ab112c2a355e4fc4cdb45f184c182458ef"

  strings:
    $s1 = "function _LLd0(s) {var _Xj3 = new Date();_Xj3.setUTCFullYear(\"2003\");if (_Xj3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LLd0(s) {var _Xj3 = new Date();_Xj3.setUTCFullYear(\"2003\");if (_Xj3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Bx1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}