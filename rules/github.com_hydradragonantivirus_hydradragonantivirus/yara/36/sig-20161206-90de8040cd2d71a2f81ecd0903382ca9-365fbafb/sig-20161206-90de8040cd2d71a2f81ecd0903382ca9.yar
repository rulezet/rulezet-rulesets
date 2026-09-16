rule sig_20161206_90de8040cd2d71a2f81ecd0903382ca9 {
  meta:
    description = "datamaliciousorder - file 20161206_90de8040cd2d71a2f81ecd0903382ca9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "827a90ffd5277041c2c177636383be9e4cfc83321a66014106bc45922616dcd6"

  strings:
    $s1 = "var vQo9 = new Function(\"s\", '{var vYEc4 = new Date();vYEc4[\"setUTCFullYear\"](\"2003\");if (vYEc4.getUTCFullYear().toString(" ascii
    $s2 = "var vQo9 = new Function(\"s\", '{var vYEc4 = new Date();vYEc4[\"setUTCFullYear\"](\"2003\");if (vYEc4.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vJj9 = s.split(\"##\"); return vJj9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vMz8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}