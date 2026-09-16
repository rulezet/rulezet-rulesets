rule sig_20161206_dcf9275cbc090391b79eac04a7d93000 {
  meta:
    description = "datamaliciousorder - file 20161206_dcf9275cbc090391b79eac04a7d93000.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64abc0691ade55a4db656085017d30a55485a4a2547add955c6c798442c1afa3"

  strings:
    $s1 = "function _HWg1(s) {var _JKo4 = new Date();_JKo4.setUTCFullYear(\"2003\");if (_JKo4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HWg1(s) {var _JKo4 = new Date();_JKo4.setUTCFullYear(\"2003\");if (_JKo4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Pp7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}