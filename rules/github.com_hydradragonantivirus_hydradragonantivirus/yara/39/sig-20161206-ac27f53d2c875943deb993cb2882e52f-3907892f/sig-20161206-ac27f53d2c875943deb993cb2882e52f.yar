rule sig_20161206_ac27f53d2c875943deb993cb2882e52f {
  meta:
    description = "datamaliciousorder - file 20161206_ac27f53d2c875943deb993cb2882e52f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a10a8fd14d439310f1aa5c0168452ad217ab95939ef1a9cf3616c241978dd7bd"

  strings:
    $s1 = "function _Gk8(s) {var _XTk7 = new Date();_XTk7.setUTCFullYear(\"2003\");if (_XTk7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gk8(s) {var _XTk7 = new Date();_XTk7.setUTCFullYear(\"2003\");if (_XTk7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _APk9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}