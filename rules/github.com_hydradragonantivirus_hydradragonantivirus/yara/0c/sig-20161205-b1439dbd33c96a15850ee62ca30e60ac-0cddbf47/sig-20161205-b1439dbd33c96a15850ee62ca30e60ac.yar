rule sig_20161205_b1439dbd33c96a15850ee62ca30e60ac {
  meta:
    description = "datamaliciousorder - file 20161205_b1439dbd33c96a15850ee62ca30e60ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d412d79312b2aa390dce761620917dbca2f68b8097936ef003bc0383c7f45299"

  strings:
    $s1 = "function _LIl9(s) {var _Nx9 = new Date();_Nx9.setUTCFullYear(\"2003\");if (_Nx9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LIl9(s) {var _Nx9 = new Date();_Nx9.setUTCFullYear(\"2003\");if (_Nx9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Fe5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}