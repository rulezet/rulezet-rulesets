rule sig_20161205_e014affc374ad0fa99b7142eb3153563 {
  meta:
    description = "datamaliciousorder - file 20161205_e014affc374ad0fa99b7142eb3153563.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abcc7b605d61a1e5f258ebf1864dd545c08bdd7dc188ac2ff505c0210e6e9151"

  strings:
    $s1 = "function _Mq5(s) {var _OXk5 = new Date();_OXk5.setUTCFullYear(\"2003\");if (_OXk5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Mq5(s) {var _OXk5 = new Date();_OXk5.setUTCFullYear(\"2003\");if (_OXk5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Oi9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}