rule sig_20161206_3893ddfa316075f6351db7317195b625 {
  meta:
    description = "datamaliciousorder - file 20161206_3893ddfa316075f6351db7317195b625.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff92cfa80c1d0fb2e64eaed21c29cce818dbccad9eb11592d7f85b6507e4fa51"

  strings:
    $s1 = "function _Oq0(s) {var _VMz6 = new Date();_VMz6.setUTCFullYear(\"2003\");if (_VMz6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Oq0(s) {var _VMz6 = new Date();_VMz6.setUTCFullYear(\"2003\");if (_VMz6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ob0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}