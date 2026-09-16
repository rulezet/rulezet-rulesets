rule sig_20161205_90d1ab295ffa75d07197781635226eab {
  meta:
    description = "datamaliciousorder - file 20161205_90d1ab295ffa75d07197781635226eab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79f87be6e730e17046c5a15b35742703b92bfe2ad2d1667db6f612d143d68609"

  strings:
    $s1 = "function _Aj4(s) {var _My4 = new Date();_My4.setUTCFullYear(\"2003\");if (_My4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Aj4(s) {var _My4 = new Date();_My4.setUTCFullYear(\"2003\");if (_My4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Dw1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}