rule sig_20161205_fa558a3f190478d0411a3b037c49ecd1 {
  meta:
    description = "datamaliciousorder - file 20161205_fa558a3f190478d0411a3b037c49ecd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26ba3b70d022cf6b0e5d3fb886cb2385d4606cd5034329bc10f9b9b432a6ab7c"

  strings:
    $s1 = "function _YGg9(s) {var _KTb5 = new Date();_KTb5.setUTCFullYear(\"2003\");if (_KTb5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YGg9(s) {var _KTb5 = new Date();_KTb5.setUTCFullYear(\"2003\");if (_KTb5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Lr1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}