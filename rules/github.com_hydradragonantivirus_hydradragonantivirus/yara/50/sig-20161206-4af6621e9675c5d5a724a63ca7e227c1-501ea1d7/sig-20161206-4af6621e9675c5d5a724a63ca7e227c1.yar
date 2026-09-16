rule sig_20161206_4af6621e9675c5d5a724a63ca7e227c1 {
  meta:
    description = "datamaliciousorder - file 20161206_4af6621e9675c5d5a724a63ca7e227c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73ab63b2565c4c86debdc6c88c74517be947b48528e587719d748ca2656181f4"

  strings:
    $s1 = "function _Ud4(s) {var _Uh6 = new Date();_Uh6.setUTCFullYear(\"2003\");if (_Uh6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ud4(s) {var _Uh6 = new Date();_Uh6.setUTCFullYear(\"2003\");if (_Uh6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Hw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}