rule sig_20161206_f6ea2e343814077150a09d77805239cc {
  meta:
    description = "datamaliciousorder - file 20161206_f6ea2e343814077150a09d77805239cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1503edfa7f089da89e24bf777a6f21100e8e7ffceda4477d58e9f45686b45a8f"

  strings:
    $s1 = "function _St7(s) {var _RRd2 = new Date();_RRd2.setUTCFullYear(\"2003\");if (_RRd2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _St7(s) {var _RRd2 = new Date();_RRd2.setUTCFullYear(\"2003\");if (_RRd2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _GKe4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}