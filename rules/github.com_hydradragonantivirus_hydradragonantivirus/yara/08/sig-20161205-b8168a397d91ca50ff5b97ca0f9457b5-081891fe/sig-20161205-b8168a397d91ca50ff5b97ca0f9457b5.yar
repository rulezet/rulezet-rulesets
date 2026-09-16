rule sig_20161205_b8168a397d91ca50ff5b97ca0f9457b5 {
  meta:
    description = "datamaliciousorder - file 20161205_b8168a397d91ca50ff5b97ca0f9457b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cfa9fe4ca2c6bca7293d970262facf886043c268c65f6fbec3acef30134e9c6"

  strings:
    $s1 = "function _ZGj0(s) {var _Kh1 = new Date();_Kh1.setUTCFullYear(\"2003\");if (_Kh1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZGj0(s) {var _Kh1 = new Date();_Kh1.setUTCFullYear(\"2003\");if (_Kh1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _CGy4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}