rule sig_20161206_53301a9cab78cfb2d005c6d6fb7706c5 {
  meta:
    description = "datamaliciousorder - file 20161206_53301a9cab78cfb2d005c6d6fb7706c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ecd4b80d335106f27799b9362423ed61216f579ae964171f60c48918a9c9664"

  strings:
    $s1 = "function _Xe6(s) {var _Ou6 = new Date();_Ou6.setUTCFullYear(\"2003\");if (_Ou6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xe6(s) {var _Ou6 = new Date();_Ou6.setUTCFullYear(\"2003\");if (_Ou6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Yu2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}