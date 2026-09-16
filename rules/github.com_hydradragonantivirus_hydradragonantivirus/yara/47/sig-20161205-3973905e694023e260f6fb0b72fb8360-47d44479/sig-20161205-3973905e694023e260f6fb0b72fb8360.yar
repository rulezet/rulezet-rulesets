rule sig_20161205_3973905e694023e260f6fb0b72fb8360 {
  meta:
    description = "datamaliciousorder - file 20161205_3973905e694023e260f6fb0b72fb8360.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "118424d637a33dfd14487d24271446426be6a55dfa41b6c0849671c23fca4920"

  strings:
    $s1 = "function _WWi5(s) {var _Ly2 = new Date();_Ly2.setUTCFullYear(\"2003\");if (_Ly2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _WWi5(s) {var _Ly2 = new Date();_Ly2.setUTCFullYear(\"2003\");if (_Ly2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _XSt4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}