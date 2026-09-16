rule sig_20161206_73e02c8ce98e0cdc55356ca9a45d7181 {
  meta:
    description = "datamaliciousorder - file 20161206_73e02c8ce98e0cdc55356ca9a45d7181.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c2c19599d1999356e6591a5633e77a2a76fe2b4e723c5b69e2f34bb436842cf"

  strings:
    $s1 = "function _VXe8(s) {var _LOq2 = new Date();_LOq2.setUTCFullYear(\"2003\");if (_LOq2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VXe8(s) {var _LOq2 = new Date();_LOq2.setUTCFullYear(\"2003\");if (_LOq2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Cl1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}