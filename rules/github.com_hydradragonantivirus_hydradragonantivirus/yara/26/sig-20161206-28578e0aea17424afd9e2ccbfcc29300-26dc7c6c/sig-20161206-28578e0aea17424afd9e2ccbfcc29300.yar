rule sig_20161206_28578e0aea17424afd9e2ccbfcc29300 {
  meta:
    description = "datamaliciousorder - file 20161206_28578e0aea17424afd9e2ccbfcc29300.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d4c20bfde9b5efeac3cc198e7e4c42d95194ceeddf686e98c5708908bcd58bf"

  strings:
    $s1 = "function _My9(s) {var _EFl1 = new Date();_EFl1.setUTCFullYear(\"2003\");if (_EFl1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _My9(s) {var _EFl1 = new Date();_EFl1.setUTCFullYear(\"2003\");if (_EFl1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Fh7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}