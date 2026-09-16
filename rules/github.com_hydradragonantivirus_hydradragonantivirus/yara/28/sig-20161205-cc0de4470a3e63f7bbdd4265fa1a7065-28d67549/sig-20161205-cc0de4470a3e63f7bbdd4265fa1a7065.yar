rule sig_20161205_cc0de4470a3e63f7bbdd4265fa1a7065 {
  meta:
    description = "datamaliciousorder - file 20161205_cc0de4470a3e63f7bbdd4265fa1a7065.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f522483aefcc680280da99b62a05250e9b20fdf57b955d7baf9779af07628388"

  strings:
    $s1 = "function _IAv7(s) {var _BUf5 = new Date();_BUf5.setUTCFullYear(\"2003\");if (_BUf5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IAv7(s) {var _BUf5 = new Date();_BUf5.setUTCFullYear(\"2003\");if (_BUf5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Kj0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}