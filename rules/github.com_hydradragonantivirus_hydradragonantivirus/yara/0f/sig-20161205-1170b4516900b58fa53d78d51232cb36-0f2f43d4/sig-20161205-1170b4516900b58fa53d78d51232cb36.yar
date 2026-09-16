rule sig_20161205_1170b4516900b58fa53d78d51232cb36 {
  meta:
    description = "datamaliciousorder - file 20161205_1170b4516900b58fa53d78d51232cb36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b139a1e2d37ba6705e87b05adfa8c6b7a4b42f914b7cb82809ca6a4c758af4a"

  strings:
    $s1 = "function _FTt8(s) {var _NNr5 = new Date();_NNr5.setUTCFullYear(\"2003\");if (_NNr5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FTt8(s) {var _NNr5 = new Date();_NNr5.setUTCFullYear(\"2003\");if (_NNr5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _NZq8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}