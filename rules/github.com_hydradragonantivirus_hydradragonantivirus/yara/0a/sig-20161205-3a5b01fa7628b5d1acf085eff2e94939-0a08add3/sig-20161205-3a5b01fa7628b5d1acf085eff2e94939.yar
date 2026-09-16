rule sig_20161205_3a5b01fa7628b5d1acf085eff2e94939 {
  meta:
    description = "datamaliciousorder - file 20161205_3a5b01fa7628b5d1acf085eff2e94939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d4e845bdef3ef35b095a0f79b0d8360affd0c8bf20d5e5ca04210ab9767e26b"

  strings:
    $s1 = "function _XMc5(s) {var _Mt5 = new Date();_Mt5.setUTCFullYear(\"2003\");if (_Mt5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _XMc5(s) {var _Mt5 = new Date();_Mt5.setUTCFullYear(\"2003\");if (_Mt5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _PPj1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}