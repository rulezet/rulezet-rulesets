rule sig_20161206_124e588c69fc11cd6f15250a459af30b {
  meta:
    description = "datamaliciousorder - file 20161206_124e588c69fc11cd6f15250a459af30b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a110f30742c6305a8ee5e8995e02b1b09121245d6344028d1c1960972760cbc9"

  strings:
    $s1 = "function _BNp7(s) {var _ILh8 = new Date();_ILh8.setUTCFullYear(\"2003\");if (_ILh8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BNp7(s) {var _ILh8 = new Date();_ILh8.setUTCFullYear(\"2003\");if (_ILh8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _CLg6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}