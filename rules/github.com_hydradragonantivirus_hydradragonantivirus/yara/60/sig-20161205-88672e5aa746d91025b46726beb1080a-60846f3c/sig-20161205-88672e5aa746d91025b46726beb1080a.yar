rule sig_20161205_88672e5aa746d91025b46726beb1080a {
  meta:
    description = "datamaliciousorder - file 20161205_88672e5aa746d91025b46726beb1080a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b60c944675bbf5095db47fba7cc61c01dcbff455b7a71f68e02fde93f4181606"

  strings:
    $s1 = "function _RNd2(s) {var _Px4 = new Date();_Px4.setUTCFullYear(\"2003\");if (_Px4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _RNd2(s) {var _Px4 = new Date();_Px4.setUTCFullYear(\"2003\");if (_Px4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Bb8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}