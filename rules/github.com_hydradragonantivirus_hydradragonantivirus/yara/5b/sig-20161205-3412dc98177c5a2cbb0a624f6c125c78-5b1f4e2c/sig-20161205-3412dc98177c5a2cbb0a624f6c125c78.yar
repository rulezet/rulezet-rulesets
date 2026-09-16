rule sig_20161205_3412dc98177c5a2cbb0a624f6c125c78 {
  meta:
    description = "datamaliciousorder - file 20161205_3412dc98177c5a2cbb0a624f6c125c78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a166a61495117d917bda86ca64a294a522d8c17d5d3668c4f1e39531ab1ea685"

  strings:
    $s1 = "function _Vf5(s) {var _GVf3 = new Date();_GVf3.setUTCFullYear(\"2003\");if (_GVf3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Vf5(s) {var _GVf3 = new Date();_GVf3.setUTCFullYear(\"2003\");if (_GVf3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ki4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}