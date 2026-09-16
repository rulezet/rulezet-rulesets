rule sig_20161206_0f3d777804778eb5dcc2f36b8b7f80dc {
  meta:
    description = "datamaliciousorder - file 20161206_0f3d777804778eb5dcc2f36b8b7f80dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "763d193eb819bf2d37456c05fa8e9c8e7e27fbaa0a607e8ad0bce8eaaf1f138b"

  strings:
    $s1 = "function _QCb0(s) {var _Ha0 = new Date();_Ha0.setUTCFullYear(\"2003\");if (_Ha0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QCb0(s) {var _Ha0 = new Date();_Ha0.setUTCFullYear(\"2003\");if (_Ha0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _IAz4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}