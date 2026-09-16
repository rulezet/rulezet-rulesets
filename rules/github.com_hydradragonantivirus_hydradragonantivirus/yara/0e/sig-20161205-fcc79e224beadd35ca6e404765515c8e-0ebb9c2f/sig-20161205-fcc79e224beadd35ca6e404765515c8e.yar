rule sig_20161205_fcc79e224beadd35ca6e404765515c8e {
  meta:
    description = "datamaliciousorder - file 20161205_fcc79e224beadd35ca6e404765515c8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c2046363a622530ef9a78d16d8dd48de310713e17d688f5c39ca3a2de1f4c9a"

  strings:
    $s1 = "function _Lm4(s) {var _COg5 = new Date();_COg5.setUTCFullYear(\"2003\");if (_COg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Lm4(s) {var _COg5 = new Date();_COg5.setUTCFullYear(\"2003\");if (_COg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Sr6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}