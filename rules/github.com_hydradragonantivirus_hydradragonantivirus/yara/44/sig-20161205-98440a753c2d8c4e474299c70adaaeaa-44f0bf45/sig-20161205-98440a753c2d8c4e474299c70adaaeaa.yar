rule sig_20161205_98440a753c2d8c4e474299c70adaaeaa {
  meta:
    description = "datamaliciousorder - file 20161205_98440a753c2d8c4e474299c70adaaeaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a92b4b38d6c44212f37f56014a0c0a3601f4a71dcf1067d2ed566175b1943408"

  strings:
    $s1 = "function _Cp7(s) {var _Fs2 = new Date();_Fs2.setUTCFullYear(\"2003\");if (_Fs2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cp7(s) {var _Fs2 = new Date();_Fs2.setUTCFullYear(\"2003\");if (_Fs2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Jw5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}