rule sig_20161206_808b78d0b29e6eb37f2f0f86ba8cae9f {
  meta:
    description = "datamaliciousorder - file 20161206_808b78d0b29e6eb37f2f0f86ba8cae9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c3f9045a7b5f6fdc83160f8935625f27c7ad27aff553df02f451489863124bb"

  strings:
    $s1 = "function _Pl7(s) {var _Dk6 = new Date();_Dk6.setUTCFullYear(\"2003\");if (_Dk6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pl7(s) {var _Dk6 = new Date();_Dk6.setUTCFullYear(\"2003\");if (_Dk6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Bh3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}