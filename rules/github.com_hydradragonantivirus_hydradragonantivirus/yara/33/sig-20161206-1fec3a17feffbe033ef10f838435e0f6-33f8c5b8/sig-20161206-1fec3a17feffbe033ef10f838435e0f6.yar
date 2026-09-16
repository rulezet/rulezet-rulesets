rule sig_20161206_1fec3a17feffbe033ef10f838435e0f6 {
  meta:
    description = "datamaliciousorder - file 20161206_1fec3a17feffbe033ef10f838435e0f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64973ad1e2b622425ca88aa4bbb7493fc2e684871b256888392ad0ecb51bb350"

  strings:
    $s1 = "function _Uu9(s) {var _SAq3 = new Date();_SAq3.setUTCFullYear(\"2003\");if (_SAq3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Uu9(s) {var _SAq3 = new Date();_SAq3.setUTCFullYear(\"2003\");if (_SAq3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YYw9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}