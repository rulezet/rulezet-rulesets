rule sig_20161206_5571eecfe2e82855049c6ff26a8f5bbe {
  meta:
    description = "datamaliciousorder - file 20161206_5571eecfe2e82855049c6ff26a8f5bbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00eb53453702d7580b001a1a42af745100e844c0368f477c8624b5f146d74f39"

  strings:
    $s1 = "function _OTa4(s) {var _Ha1 = new Date();_Ha1.setUTCFullYear(\"2003\");if (_Ha1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OTa4(s) {var _Ha1 = new Date();_Ha1.setUTCFullYear(\"2003\");if (_Ha1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Wh8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}