rule sig_20161205_6d714663fc83dae2421d455696fbf42b {
  meta:
    description = "datamaliciousorder - file 20161205_6d714663fc83dae2421d455696fbf42b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99462b3505b2671724c75deabc72983f32c534815d1e9e82504c0aa483efa367"

  strings:
    $s1 = "function _Qc3(s) {var _Cu9 = new Date();_Cu9.setUTCFullYear(\"2003\");if (_Cu9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qc3(s) {var _Cu9 = new Date();_Cu9.setUTCFullYear(\"2003\");if (_Cu9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Gt0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}