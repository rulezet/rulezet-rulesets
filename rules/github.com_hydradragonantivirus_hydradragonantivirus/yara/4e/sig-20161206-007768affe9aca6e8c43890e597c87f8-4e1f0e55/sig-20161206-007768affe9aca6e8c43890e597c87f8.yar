rule sig_20161206_007768affe9aca6e8c43890e597c87f8 {
  meta:
    description = "datamaliciousorder - file 20161206_007768affe9aca6e8c43890e597c87f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94a08e0c5305d8df24c5a5d5fb69add43c1b1da479bd78b43263ab5129e32de5"

  strings:
    $s1 = "function _SVn3(s) {var _Iu7 = new Date();_Iu7.setUTCFullYear(\"2003\");if (_Iu7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SVn3(s) {var _Iu7 = new Date();_Iu7.setUTCFullYear(\"2003\");if (_Iu7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _PFc6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}