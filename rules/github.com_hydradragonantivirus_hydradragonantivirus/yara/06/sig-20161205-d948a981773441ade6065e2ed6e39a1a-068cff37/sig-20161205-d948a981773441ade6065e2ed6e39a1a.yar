rule sig_20161205_d948a981773441ade6065e2ed6e39a1a {
  meta:
    description = "datamaliciousorder - file 20161205_d948a981773441ade6065e2ed6e39a1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc0e646599f29eb723b6cf94bf2318640ba8245ff5b63bda29a34209ce4ca47b"

  strings:
    $s1 = "function _PYr3(s) {var _Nx0 = new Date();_Nx0.setUTCFullYear(\"2003\");if (_Nx0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PYr3(s) {var _Nx0 = new Date();_Nx0.setUTCFullYear(\"2003\");if (_Nx0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Uu4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}