rule sig_20161205_3573a058be08bfb7364c27c448b84274 {
  meta:
    description = "datamaliciousorder - file 20161205_3573a058be08bfb7364c27c448b84274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "525654c75ca2809136aa9c888ba3ed42b64fd108feabf145075a9fd96b5e3a19"

  strings:
    $s1 = "function _Ig0(s) {var _BKi3 = new Date();_BKi3.setUTCFullYear(\"2003\");if (_BKi3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ig0(s) {var _BKi3 = new Date();_BKi3.setUTCFullYear(\"2003\");if (_BKi3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UHu5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}