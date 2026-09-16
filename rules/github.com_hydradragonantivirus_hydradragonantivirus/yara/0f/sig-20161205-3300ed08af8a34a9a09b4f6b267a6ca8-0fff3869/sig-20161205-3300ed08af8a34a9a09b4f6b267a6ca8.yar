rule sig_20161205_3300ed08af8a34a9a09b4f6b267a6ca8 {
  meta:
    description = "datamaliciousorder - file 20161205_3300ed08af8a34a9a09b4f6b267a6ca8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4e739cbe65f216910027bd09978abaf3817438a1d22e3ffbcf6cdd513302a1"

  strings:
    $s1 = "function _Xm0(s) {var _QWl5 = new Date();_QWl5.setUTCFullYear(\"2003\");if (_QWl5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xm0(s) {var _QWl5 = new Date();_QWl5.setUTCFullYear(\"2003\");if (_QWl5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ih9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}