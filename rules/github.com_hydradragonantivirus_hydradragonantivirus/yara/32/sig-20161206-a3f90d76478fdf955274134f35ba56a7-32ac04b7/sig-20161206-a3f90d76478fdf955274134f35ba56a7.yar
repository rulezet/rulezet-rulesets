rule sig_20161206_a3f90d76478fdf955274134f35ba56a7 {
  meta:
    description = "datamaliciousorder - file 20161206_a3f90d76478fdf955274134f35ba56a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481ac96d2380bf9baf71066614661c5836f0e32ca745402d56b238fcc48b36be"

  strings:
    $s1 = "var vTUv0 = new Function(\"s\", '{var vDWu7 = new Date();vDWu7[\"setUTCFullYear\"](\"2003\");if (vDWu7.getUTCFullYear().toString" ascii
    $s2 = "var vTUv0 = new Function(\"s\", '{var vDWu7 = new Date();vDWu7[\"setUTCFullYear\"](\"2003\");if (vDWu7.getUTCFullYear().toString" ascii
    $s3 = "function vQw1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vMIm5 = s.split(\"##\"); return vMIm5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}