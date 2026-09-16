rule sig_20161206_ab1da5c34ec14b4ae7a889a0f699eca0 {
  meta:
    description = "datamaliciousorder - file 20161206_ab1da5c34ec14b4ae7a889a0f699eca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "864c7a2a47498b85fe5e17a2f24222a4d7af3eee8c1253e02d5a04c43a312caf"

  strings:
    $s1 = "function _Lt6(s) {var _LLk6 = new Date();_LLk6.setUTCFullYear(\"2003\");if (_LLk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Lt6(s) {var _LLk6 = new Date();_LLk6.setUTCFullYear(\"2003\");if (_LLk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Kf5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}