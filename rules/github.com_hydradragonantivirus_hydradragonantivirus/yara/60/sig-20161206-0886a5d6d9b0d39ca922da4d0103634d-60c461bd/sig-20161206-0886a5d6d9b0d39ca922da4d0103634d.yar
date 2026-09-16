rule sig_20161206_0886a5d6d9b0d39ca922da4d0103634d {
  meta:
    description = "datamaliciousorder - file 20161206_0886a5d6d9b0d39ca922da4d0103634d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7df68bbbf295330976e49ab5b8eb1d8d7046cd429854a97b7d12bcac91c5f762"

  strings:
    $s1 = "function _PSh7(s) {var _WBt6 = new Date();_WBt6.setUTCFullYear(\"2003\");if (_WBt6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PSh7(s) {var _WBt6 = new Date();_WBt6.setUTCFullYear(\"2003\");if (_WBt6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _AMk2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}