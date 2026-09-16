rule sig_20161206_09eec2a3bc1041723788fbc4e1fe48b4 {
  meta:
    description = "datamaliciousorder - file 20161206_09eec2a3bc1041723788fbc4e1fe48b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddeae7521243d1373dbb164e69a2402d23836adb2e49bc488725bd429aebd63"

  strings:
    $s1 = "function _WHa8(s) {var _QSx3 = new Date();_QSx3.setUTCFullYear(\"2003\");if (_QSx3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WHa8(s) {var _QSx3 = new Date();_QSx3.setUTCFullYear(\"2003\");if (_QSx3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Kp3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}