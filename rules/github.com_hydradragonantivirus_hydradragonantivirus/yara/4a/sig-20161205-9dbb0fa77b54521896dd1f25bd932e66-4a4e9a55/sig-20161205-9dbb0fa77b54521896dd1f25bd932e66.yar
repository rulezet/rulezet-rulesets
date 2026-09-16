rule sig_20161205_9dbb0fa77b54521896dd1f25bd932e66 {
  meta:
    description = "datamaliciousorder - file 20161205_9dbb0fa77b54521896dd1f25bd932e66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2190299f1239b971102b2040a0126dbe952c6ec9258c446a7c5887af7fcc1ff2"

  strings:
    $s1 = "function _Ve3(s) {var _Gf9 = new Date();_Gf9.setUTCFullYear(\"2003\");if (_Gf9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ve3(s) {var _Gf9 = new Date();_Gf9.setUTCFullYear(\"2003\");if (_Gf9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _NVs7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}