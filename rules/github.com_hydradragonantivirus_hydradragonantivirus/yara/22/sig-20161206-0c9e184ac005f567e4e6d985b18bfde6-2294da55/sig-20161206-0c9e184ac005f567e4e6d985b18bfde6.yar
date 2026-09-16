rule sig_20161206_0c9e184ac005f567e4e6d985b18bfde6 {
  meta:
    description = "datamaliciousorder - file 20161206_0c9e184ac005f567e4e6d985b18bfde6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56944681696ee9921510d81f14507f03faed04428703a43a806ac2553aeb96aa"

  strings:
    $s1 = "function _Kw7(s) {var _RSa8 = new Date();_RSa8.setUTCFullYear(\"2003\");if (_RSa8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kw7(s) {var _RSa8 = new Date();_RSa8.setUTCFullYear(\"2003\");if (_RSa8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _OIw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}