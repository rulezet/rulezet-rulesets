rule sig_20161206_58833e84aa10825c67dfce7288f4b8a7 {
  meta:
    description = "datamaliciousorder - file 20161206_58833e84aa10825c67dfce7288f4b8a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c1c8df41d91fd98887a007db8f8b91872a6cdbd972005020ec423539c221775"

  strings:
    $s1 = "function _OYx7(s) {var _Av6 = new Date();_Av6.setUTCFullYear(\"2003\");if (_Av6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OYx7(s) {var _Av6 = new Date();_Av6.setUTCFullYear(\"2003\");if (_Av6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _BLf0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}