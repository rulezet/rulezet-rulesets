rule sig_20161205_7cf7ebc270b0d430d68d6d1a5f9058fa {
  meta:
    description = "datamaliciousorder - file 20161205_7cf7ebc270b0d430d68d6d1a5f9058fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73157771ac7fef4e29de77309abbf0835bdb1f1a0d9674a1dc27fe5b93c61075"

  strings:
    $s1 = "function _RXe8(s) {var _Nl1 = new Date();_Nl1.setUTCFullYear(\"2003\");if (_Nl1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _RXe8(s) {var _Nl1 = new Date();_Nl1.setUTCFullYear(\"2003\");if (_Nl1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _EZm7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}