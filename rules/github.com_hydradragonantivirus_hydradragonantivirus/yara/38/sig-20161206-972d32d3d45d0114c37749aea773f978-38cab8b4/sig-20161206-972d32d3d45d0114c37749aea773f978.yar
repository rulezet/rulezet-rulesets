rule sig_20161206_972d32d3d45d0114c37749aea773f978 {
  meta:
    description = "datamaliciousorder - file 20161206_972d32d3d45d0114c37749aea773f978.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "616d8c9a41b1cd650dcfca99ffb4a816764a86cc767bf4423086811b4cc67092"

  strings:
    $s1 = "function _CFg4(s) {var _BGj3 = new Date();_BGj3.setUTCFullYear(\"2003\");if (_BGj3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CFg4(s) {var _BGj3 = new Date();_BGj3.setUTCFullYear(\"2003\");if (_BGj3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Le3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}