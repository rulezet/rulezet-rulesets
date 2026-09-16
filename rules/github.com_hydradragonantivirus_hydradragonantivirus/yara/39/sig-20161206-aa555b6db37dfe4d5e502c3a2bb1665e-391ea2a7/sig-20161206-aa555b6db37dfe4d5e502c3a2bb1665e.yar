rule sig_20161206_aa555b6db37dfe4d5e502c3a2bb1665e {
  meta:
    description = "datamaliciousorder - file 20161206_aa555b6db37dfe4d5e502c3a2bb1665e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80bcb96acd3ff7fde543dca640ba8222bc1801d6efe7d1832706728de70999c6"

  strings:
    $s1 = "function _IOd7(s) {var _ENl3 = new Date();_ENl3.setUTCFullYear(\"2003\");if (_ENl3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IOd7(s) {var _ENl3 = new Date();_ENl3.setUTCFullYear(\"2003\");if (_ENl3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _QOf4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}