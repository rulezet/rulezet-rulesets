rule sig_20161205_68bb06732c39ba6463f32b8bcca60632 {
  meta:
    description = "datamaliciousorder - file 20161205_68bb06732c39ba6463f32b8bcca60632.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a53f9d5213aea33f49e7f679fb5c436da2890430c0c3a4611638d3a64154784d"

  strings:
    $s1 = "function _Ia0(s) {var _Dx6 = new Date();_Dx6.setUTCFullYear(\"2003\");if (_Dx6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ia0(s) {var _Dx6 = new Date();_Dx6.setUTCFullYear(\"2003\");if (_Dx6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Mm9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}