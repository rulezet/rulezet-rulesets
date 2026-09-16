rule sig_20161205_46739413ca748bc3214d6f9616560b78 {
  meta:
    description = "datamaliciousorder - file 20161205_46739413ca748bc3214d6f9616560b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fb0aa0836f7380fb0e3e6c918cd10603413ce0316aabadf535ad32d3f89782f"

  strings:
    $s1 = "function _ZTe6(s) {var _Xr8 = new Date();_Xr8.setUTCFullYear(\"2003\");if (_Xr8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZTe6(s) {var _Xr8 = new Date();_Xr8.setUTCFullYear(\"2003\");if (_Xr8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Jz2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}