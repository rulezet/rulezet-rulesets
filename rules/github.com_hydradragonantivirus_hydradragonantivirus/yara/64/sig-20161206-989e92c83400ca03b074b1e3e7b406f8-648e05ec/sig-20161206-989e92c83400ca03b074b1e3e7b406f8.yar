rule sig_20161206_989e92c83400ca03b074b1e3e7b406f8 {
  meta:
    description = "datamaliciousorder - file 20161206_989e92c83400ca03b074b1e3e7b406f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88adfba0caf1654772471c923cb84ced572bdfcc0902f87065003184dc66297b"

  strings:
    $s1 = "function _Sd7(s) {var _Vd0 = new Date();_Vd0.setUTCFullYear(\"2003\");if (_Vd0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sd7(s) {var _Vd0 = new Date();_Vd0.setUTCFullYear(\"2003\");if (_Vd0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Kq7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}