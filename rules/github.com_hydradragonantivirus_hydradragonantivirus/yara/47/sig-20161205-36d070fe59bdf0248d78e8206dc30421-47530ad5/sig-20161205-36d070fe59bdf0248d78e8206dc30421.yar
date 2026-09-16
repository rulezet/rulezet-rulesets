rule sig_20161205_36d070fe59bdf0248d78e8206dc30421 {
  meta:
    description = "datamaliciousorder - file 20161205_36d070fe59bdf0248d78e8206dc30421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "438e766caa1e317c748f21d09ca38c81c7efb91992b5f0d30d7dcceea5fd422d"

  strings:
    $s1 = "function _LFu6(s) {var _Xy3 = new Date();_Xy3.setUTCFullYear(\"2003\");if (_Xy3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LFu6(s) {var _Xy3 = new Date();_Xy3.setUTCFullYear(\"2003\");if (_Xy3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ui8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}