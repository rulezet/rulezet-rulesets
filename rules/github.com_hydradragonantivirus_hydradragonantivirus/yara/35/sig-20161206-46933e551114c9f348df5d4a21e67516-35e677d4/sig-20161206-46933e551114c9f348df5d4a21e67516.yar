rule sig_20161206_46933e551114c9f348df5d4a21e67516 {
  meta:
    description = "datamaliciousorder - file 20161206_46933e551114c9f348df5d4a21e67516.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "618ca2d2a5c21e7ef028134e35f4d9e99202115b0de479d789bc7df838844072"

  strings:
    $s1 = "var vHm9 = new Function(\"s\", '{var vKs5 = new Date();vKs5[\"setUTCFullYear\"](\"2003\");if (vKs5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vHm9 = new Function(\"s\", '{var vKs5 = new Date();vKs5[\"setUTCFullYear\"](\"2003\");if (vKs5.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vKMj9 = s.split(\"##\"); return vKMj9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vHUu2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}