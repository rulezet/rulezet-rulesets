rule sig_20161206_d2a296f41cea177266eedad18866ee07 {
  meta:
    description = "datamaliciousorder - file 20161206_d2a296f41cea177266eedad18866ee07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f91019d2d1f0f6dfbf27fc97628aa1a2bc5a5b13c9bcc62ea9fb8a139da129e7"

  strings:
    $s1 = "function _Bo4(s) {var _WNf5 = new Date();_WNf5.setUTCFullYear(\"2003\");if (_WNf5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bo4(s) {var _WNf5 = new Date();_WNf5.setUTCFullYear(\"2003\");if (_WNf5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ONi6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}