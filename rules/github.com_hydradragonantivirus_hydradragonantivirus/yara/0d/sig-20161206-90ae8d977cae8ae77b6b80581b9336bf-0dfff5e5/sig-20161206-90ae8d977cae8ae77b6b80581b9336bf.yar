rule sig_20161206_90ae8d977cae8ae77b6b80581b9336bf {
  meta:
    description = "datamaliciousorder - file 20161206_90ae8d977cae8ae77b6b80581b9336bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1930f7b1b3b34cf235764b29ee1b407bb4ebdfb3dc1dd09a72b80f33ff77dfa"

  strings:
    $s1 = "function _GWu2(s) {var _Fh9 = new Date();_Fh9.setUTCFullYear(\"2003\");if (_Fh9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GWu2(s) {var _Fh9 = new Date();_Fh9.setUTCFullYear(\"2003\");if (_Fh9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FYp6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}