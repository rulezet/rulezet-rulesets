rule sig_20161206_341d8dcd1c234de641e6faa600d4915f {
  meta:
    description = "datamaliciousorder - file 20161206_341d8dcd1c234de641e6faa600d4915f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6748ba17bca6fb6b41fcc39709eabd7243dbb2f5f3f6ba4ec028da4971d7bdd"

  strings:
    $s1 = "function _Uv0(s) {var _KGm4 = new Date();_KGm4.setUTCFullYear(\"2003\");if (_KGm4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Uv0(s) {var _KGm4 = new Date();_KGm4.setUTCFullYear(\"2003\");if (_KGm4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _EQe4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}