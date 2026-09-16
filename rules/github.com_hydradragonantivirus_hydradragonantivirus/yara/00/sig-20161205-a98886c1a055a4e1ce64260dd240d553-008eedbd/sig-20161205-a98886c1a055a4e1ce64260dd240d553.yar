rule sig_20161205_a98886c1a055a4e1ce64260dd240d553 {
  meta:
    description = "datamaliciousorder - file 20161205_a98886c1a055a4e1ce64260dd240d553.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df4f7ba222d8be36d5c9b19b452829eb0e0b362372a006e22f3e884bf46155e2"

  strings:
    $s1 = "function _LLf5(s) {var _Ik8 = new Date();_Ik8.setUTCFullYear(\"2003\");if (_Ik8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LLf5(s) {var _Ik8 = new Date();_Ik8.setUTCFullYear(\"2003\");if (_Ik8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _VKh7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}