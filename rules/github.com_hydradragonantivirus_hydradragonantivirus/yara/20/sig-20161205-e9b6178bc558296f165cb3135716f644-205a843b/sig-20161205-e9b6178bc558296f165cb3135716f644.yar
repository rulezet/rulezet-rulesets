rule sig_20161205_e9b6178bc558296f165cb3135716f644 {
  meta:
    description = "datamaliciousorder - file 20161205_e9b6178bc558296f165cb3135716f644.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01a6fb7e4121dbe52edeb4ebc03691970c581bad2092ab0fc59c0da51b8a99a6"

  strings:
    $s1 = "function _Nl7(s) {var _Kj7 = new Date();_Kj7.setUTCFullYear(\"2003\");if (_Kj7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Nl7(s) {var _Kj7 = new Date();_Kj7.setUTCFullYear(\"2003\");if (_Kj7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ir8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}