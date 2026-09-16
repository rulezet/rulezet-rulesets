rule sig_20161206_f8fd6dccf4ca072f986872bdfbf18faa {
  meta:
    description = "datamaliciousorder - file 20161206_f8fd6dccf4ca072f986872bdfbf18faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dae900f9da91047fbb0a5110eebeaa694e51e411961bfb9b50d6602464dc2b0d"

  strings:
    $s1 = "function _Jx7(s) {var _Po0 = new Date();_Po0.setUTCFullYear(\"2003\");if (_Po0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jx7(s) {var _Po0 = new Date();_Po0.setUTCFullYear(\"2003\");if (_Po0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Lj2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}