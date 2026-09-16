rule sig_20161206_911be4d3cbb947d3845ebe4563103f3c {
  meta:
    description = "datamaliciousorder - file 20161206_911be4d3cbb947d3845ebe4563103f3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5863b6b303edc26088f464f8a8dd5cb5099cd21256fab965087ef7e16cef3b9"

  strings:
    $s1 = "var vSIb9 = new Function(\"s\", '{var vZz6 = new Date();vZz6[\"setUTCFullYear\"](\"2003\");if (vZz6.getUTCFullYear().toString(10" ascii
    $s2 = "var vSIb9 = new Function(\"s\", '{var vZz6 = new Date();vZz6[\"setUTCFullYear\"](\"2003\");if (vZz6.getUTCFullYear().toString(10" ascii
    $s3 = "function vYZc4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vSz3 = s.split(\"##\"); return vSz3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}