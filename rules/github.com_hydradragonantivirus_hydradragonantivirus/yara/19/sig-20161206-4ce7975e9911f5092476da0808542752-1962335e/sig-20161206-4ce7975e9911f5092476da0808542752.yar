rule sig_20161206_4ce7975e9911f5092476da0808542752 {
  meta:
    description = "datamaliciousorder - file 20161206_4ce7975e9911f5092476da0808542752.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f828b13ee5e0e716a47b3d599a7d8fc3b00d23df6e0a6c5ddd051282928b4288"

  strings:
    $s1 = "function _ERd4(s) {var _Vv0 = new Date();_Vv0.setUTCFullYear(\"2003\");if (_Vv0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ERd4(s) {var _Vv0 = new Date();_Vv0.setUTCFullYear(\"2003\");if (_Vv0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Qh0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}