rule sig_20161205_f1a105ff6d23db1eab5c7b1de60b14ff {
  meta:
    description = "datamaliciousorder - file 20161205_f1a105ff6d23db1eab5c7b1de60b14ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9073308ec911c36916cf3e4c7f2b64082f1830bec9c54a6b6c648f62fbe6cf8b"

  strings:
    $s1 = "function _PKh5(s) {var _Mp6 = new Date();_Mp6.setUTCFullYear(\"2003\");if (_Mp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PKh5(s) {var _Mp6 = new Date();_Mp6.setUTCFullYear(\"2003\");if (_Mp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _XXl0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}