rule sig_20161205_97213f9c3c152eeb6897cc4598b65c85 {
  meta:
    description = "datamaliciousorder - file 20161205_97213f9c3c152eeb6897cc4598b65c85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf8a786a78cfc9e39ad4f318fcdc6ffbd83545860a2a9067d1653f954a0f6674"

  strings:
    $s1 = "function _YLz9(s) {var _XZu5 = new Date();_XZu5.setUTCFullYear(\"2003\");if (_XZu5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YLz9(s) {var _XZu5 = new Date();_XZu5.setUTCFullYear(\"2003\");if (_XZu5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _NJu8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}