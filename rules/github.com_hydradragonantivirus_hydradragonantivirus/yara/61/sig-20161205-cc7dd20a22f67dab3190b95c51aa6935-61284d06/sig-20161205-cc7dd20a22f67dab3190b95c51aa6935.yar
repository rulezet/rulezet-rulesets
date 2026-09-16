rule sig_20161205_cc7dd20a22f67dab3190b95c51aa6935 {
  meta:
    description = "datamaliciousorder - file 20161205_cc7dd20a22f67dab3190b95c51aa6935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ede16a7e281c8f90a59e7cd5a03fff8d2eb45b2cbdcbbd5e142796db6bec7b1"

  strings:
    $s1 = "function _Ul6(s) {var _Yj3 = new Date();_Yj3.setUTCFullYear(\"2003\");if (_Yj3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ul6(s) {var _Yj3 = new Date();_Yj3.setUTCFullYear(\"2003\");if (_Yj3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _IPa7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}