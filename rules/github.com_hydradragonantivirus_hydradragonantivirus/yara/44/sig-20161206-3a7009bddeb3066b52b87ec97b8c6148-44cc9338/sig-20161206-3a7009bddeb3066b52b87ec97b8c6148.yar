rule sig_20161206_3a7009bddeb3066b52b87ec97b8c6148 {
  meta:
    description = "datamaliciousorder - file 20161206_3a7009bddeb3066b52b87ec97b8c6148.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f92e4a458bf65d22b2ce94a33237652e0d0768b24939c196a4dccce6a6194db0"

  strings:
    $s1 = "var vXIy7 = new Function(\"s\", '{var vRs6 = new Date();vRs6[\"setUTCFullYear\"](\"2003\");if (vRs6.getUTCFullYear().toString(10" ascii
    $s2 = "var vXIy7 = new Function(\"s\", '{var vRs6 = new Date();vRs6[\"setUTCFullYear\"](\"2003\");if (vRs6.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vTp0 = s.split(\"##\"); return vTp0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vSo8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}