rule sig_20161206_314b9ff88835da4505328c02a2b64504 {
  meta:
    description = "datamaliciousorder - file 20161206_314b9ff88835da4505328c02a2b64504.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25c37f468d50860fff47e4c2f9e1f42de01635483cb5df0f808b7081c7e991a6"

  strings:
    $s1 = "function _Ea6(s) {var _Ya5 = new Date();_Ya5.setUTCFullYear(\"2003\");if (_Ya5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ea6(s) {var _Ya5 = new Date();_Ya5.setUTCFullYear(\"2003\");if (_Ya5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Wx5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}