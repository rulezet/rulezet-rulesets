rule sig_20161206_6d1d5f8f7bacdb5b16aacefa7089baee {
  meta:
    description = "datamaliciousorder - file 20161206_6d1d5f8f7bacdb5b16aacefa7089baee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba33db01fbf9421ebbf61760ea5ea62851c6949ff91bea8b333b962fe1eee9a"

  strings:
    $s1 = "function _Fs4(s) {var _At2 = new Date();_At2.setUTCFullYear(\"2003\");if (_At2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fs4(s) {var _At2 = new Date();_At2.setUTCFullYear(\"2003\");if (_At2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qb2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}