rule sig_20161205_ecbaad5d2cd3f5d6f48079a3560a344a {
  meta:
    description = "datamaliciousorder - file 20161205_ecbaad5d2cd3f5d6f48079a3560a344a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfbb300fd28142cec3fb92686c9d77fa012134e769e6e82b7d5f961620448a6b"

  strings:
    $s1 = "function _XNc6(s) {var _Dy9 = new Date();_Dy9.setUTCFullYear(\"2003\");if (_Dy9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _XNc6(s) {var _Dy9 = new Date();_Dy9.setUTCFullYear(\"2003\");if (_Dy9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _KJj0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}