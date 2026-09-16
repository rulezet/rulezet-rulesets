rule sig_20161205_271cbde79b742a0a15dda4980e826228 {
  meta:
    description = "datamaliciousorder - file 20161205_271cbde79b742a0a15dda4980e826228.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "353f8cbbbcb1e7c2cb7476444d8b228846497c8319136b7c00aa1a950cc680a4"

  strings:
    $s1 = "function _Eq9(s) {var _Gg5 = new Date();_Gg5.setUTCFullYear(\"2003\");if (_Gg5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Eq9(s) {var _Gg5 = new Date();_Gg5.setUTCFullYear(\"2003\");if (_Gg5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _IQm1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}