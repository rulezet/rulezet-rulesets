rule sig_20161205_5ae51f3b2bf79122f6a2067e2f9a6e7f {
  meta:
    description = "datamaliciousorder - file 20161205_5ae51f3b2bf79122f6a2067e2f9a6e7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "346ed15fd840d08206d7531b1c6976053f24cbed4cb8ffc164a7ceba4e1de4fa"

  strings:
    $s1 = "function _POi6(s) {var _WVc7 = new Date();_WVc7.setUTCFullYear(\"2003\");if (_WVc7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _POi6(s) {var _WVc7 = new Date();_WVc7.setUTCFullYear(\"2003\");if (_WVc7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ic6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}