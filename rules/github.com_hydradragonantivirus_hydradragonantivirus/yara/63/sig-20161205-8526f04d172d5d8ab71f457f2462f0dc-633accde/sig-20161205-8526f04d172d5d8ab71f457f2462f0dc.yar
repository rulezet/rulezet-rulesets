rule sig_20161205_8526f04d172d5d8ab71f457f2462f0dc {
  meta:
    description = "datamaliciousorder - file 20161205_8526f04d172d5d8ab71f457f2462f0dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21b59c26e42253fbe95ac4c58dcb7be24f4462a97cfab636da822c4b94f1c1f4"

  strings:
    $s1 = "function _YYz7(s) {var _Mj0 = new Date();_Mj0.setUTCFullYear(\"2003\");if (_Mj0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YYz7(s) {var _Mj0 = new Date();_Mj0.setUTCFullYear(\"2003\");if (_Mj0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Oe6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}