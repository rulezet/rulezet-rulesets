rule sig_20161205_b6eedf2d7e08499de856c7b63924b1b9 {
  meta:
    description = "datamaliciousorder - file 20161205_b6eedf2d7e08499de856c7b63924b1b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dedaf28413822a1cf3f6569ca6e41fdff3bec911f1e80283d9c6655792feb818"

  strings:
    $s1 = "function _Dx7(s) {var _KZt8 = new Date();_KZt8.setUTCFullYear(\"2003\");if (_KZt8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dx7(s) {var _KZt8 = new Date();_KZt8.setUTCFullYear(\"2003\");if (_KZt8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Wp8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}