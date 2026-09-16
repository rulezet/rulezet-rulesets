rule sig_20161206_04788553a7b604a2935008a201e2bc86 {
  meta:
    description = "datamaliciousorder - file 20161206_04788553a7b604a2935008a201e2bc86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aae666451b69ac3e95fb592c2bda4f0c34587d0a373403422643531229ed0bc5"

  strings:
    $s1 = "var vZq9 = new Function(\"s\", '{var vVg5 = new Date();vVg5[\"setUTCFullYear\"](\"2003\");if (vVg5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vZq9 = new Function(\"s\", '{var vVg5 = new Date();vVg5[\"setUTCFullYear\"](\"2003\");if (vVg5.getUTCFullYear().toString(10)" ascii
    $s3 = "function vRZo9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vUIt5 = s.split(\"##\"); return vUIt5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}