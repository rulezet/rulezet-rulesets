rule sig_20161205_730a295438a460a1af1b1aa526a2a0ce {
  meta:
    description = "datamaliciousorder - file 20161205_730a295438a460a1af1b1aa526a2a0ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a00eb9c480d46e3d6fd60355b768ccf492a98916cae38cfa57e4c74ed310e6f"

  strings:
    $s1 = "function _Yf4(s) {var _Cf9 = new Date();_Cf9.setUTCFullYear(\"2003\");if (_Cf9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yf4(s) {var _Cf9 = new Date();_Cf9.setUTCFullYear(\"2003\");if (_Cf9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _IWt8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}