rule sig_20161205_b944169f7599e686c2c981db8c6b2494 {
  meta:
    description = "datamaliciousorder - file 20161205_b944169f7599e686c2c981db8c6b2494.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1937bc02e133459b94f099bb5e1d3d7d3cfcb2a5fc14f398ff5931424765812"

  strings:
    $s1 = "function _Ov0(s) {var _Cg5 = new Date();_Cg5.setUTCFullYear(\"2003\");if (_Cg5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ov0(s) {var _Cg5 = new Date();_Cg5.setUTCFullYear(\"2003\");if (_Cg5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Rc5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}