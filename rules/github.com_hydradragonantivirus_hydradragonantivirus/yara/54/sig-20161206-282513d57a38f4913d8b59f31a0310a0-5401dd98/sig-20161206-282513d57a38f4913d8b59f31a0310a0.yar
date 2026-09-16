rule sig_20161206_282513d57a38f4913d8b59f31a0310a0 {
  meta:
    description = "datamaliciousorder - file 20161206_282513d57a38f4913d8b59f31a0310a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3b167a3398b9565a2920a7b43d9bfbc7baf48acb6328925f4133c7bfb3387af"

  strings:
    $s1 = "function _Go0(s) {var _VHw2 = new Date();_VHw2.setUTCFullYear(\"2003\");if (_VHw2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Go0(s) {var _VHw2 = new Date();_VHw2.setUTCFullYear(\"2003\");if (_VHw2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _NQt2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}