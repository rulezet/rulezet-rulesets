rule sig_20161205_59dac2230323cc3d395e11aad4ceac7c {
  meta:
    description = "datamaliciousorder - file 20161205_59dac2230323cc3d395e11aad4ceac7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74ed6192cdfcd66b83a79b11025dbfc2f256be70d4518c36b1b80515cb0699af"

  strings:
    $s1 = "function _HXh9(s) {var _Dc6 = new Date();_Dc6.setUTCFullYear(\"2003\");if (_Dc6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HXh9(s) {var _Dc6 = new Date();_Dc6.setUTCFullYear(\"2003\");if (_Dc6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _St7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}