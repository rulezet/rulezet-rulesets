rule sig_20161205_719e8662fd7061a7b17f934778fc65b6 {
  meta:
    description = "datamaliciousorder - file 20161205_719e8662fd7061a7b17f934778fc65b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a73944bf4b5951bbe0d22b7d828146d9758fc5fbf167840b800c1686620652"

  strings:
    $s1 = "function _Xa3(s) {var _UGo6 = new Date();_UGo6.setUTCFullYear(\"2003\");if (_UGo6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xa3(s) {var _UGo6 = new Date();_UGo6.setUTCFullYear(\"2003\");if (_UGo6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ZPy2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}