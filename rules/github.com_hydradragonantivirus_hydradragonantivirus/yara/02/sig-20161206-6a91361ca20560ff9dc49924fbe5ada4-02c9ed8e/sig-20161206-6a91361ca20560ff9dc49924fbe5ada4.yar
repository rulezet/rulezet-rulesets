rule sig_20161206_6a91361ca20560ff9dc49924fbe5ada4 {
  meta:
    description = "datamaliciousorder - file 20161206_6a91361ca20560ff9dc49924fbe5ada4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d85e166006a8bd48e4620310afa61abb432f2f61133ad2a16e1642881282e2eb"

  strings:
    $s1 = "function _YYz9(s) {var _GJk2 = new Date();_GJk2.setUTCFullYear(\"2003\");if (_GJk2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YYz9(s) {var _GJk2 = new Date();_GJk2.setUTCFullYear(\"2003\");if (_GJk2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Jn5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}