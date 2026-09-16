rule sig_20161205_bba17631a3918dc22d7d9f2ea0e91355 {
  meta:
    description = "datamaliciousorder - file 20161205_bba17631a3918dc22d7d9f2ea0e91355.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf1e20b5b64c1f36c7032d34a942b96369a39878f0e0f920e8e6d8eef1ed8c9e"

  strings:
    $s1 = "function _VLw6(s) {var _Nr5 = new Date();_Nr5.setUTCFullYear(\"2003\");if (_Nr5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VLw6(s) {var _Nr5 = new Date();_Nr5.setUTCFullYear(\"2003\");if (_Nr5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Kx0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}