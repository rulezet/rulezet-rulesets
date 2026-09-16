rule sig_20161205_7331127f0966cf4bb94a13c68caede97 {
  meta:
    description = "datamaliciousorder - file 20161205_7331127f0966cf4bb94a13c68caede97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67dc9b92b48bc1ef27d10b6804b5e4d55999d16ca948470375396d37aaf428f6"

  strings:
    $s1 = "function _DPn7(s) {var _Gj0 = new Date();_Gj0.setUTCFullYear(\"2003\");if (_Gj0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DPn7(s) {var _Gj0 = new Date();_Gj0.setUTCFullYear(\"2003\");if (_Gj0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _HIc9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}