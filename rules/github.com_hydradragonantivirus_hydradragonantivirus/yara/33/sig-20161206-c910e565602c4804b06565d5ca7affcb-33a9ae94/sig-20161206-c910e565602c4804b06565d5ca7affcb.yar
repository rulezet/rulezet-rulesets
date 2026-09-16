rule sig_20161206_c910e565602c4804b06565d5ca7affcb {
  meta:
    description = "datamaliciousorder - file 20161206_c910e565602c4804b06565d5ca7affcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c26c54dd9a149937a1b957867d707eb9b9c86ebf268729461208ab03dd0718c"

  strings:
    $s1 = "var vKb1 = new Function(\"s\", '{var vJm0 = new Date();vJm0[\"setUTCFullYear\"](\"2003\");if (vJm0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vKb1 = new Function(\"s\", '{var vJm0 = new Date();vJm0[\"setUTCFullYear\"](\"2003\");if (vJm0.getUTCFullYear().toString(10)" ascii
    $s3 = "function vTr2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vCSo8 = s.split(\"##\"); return vCSo8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}