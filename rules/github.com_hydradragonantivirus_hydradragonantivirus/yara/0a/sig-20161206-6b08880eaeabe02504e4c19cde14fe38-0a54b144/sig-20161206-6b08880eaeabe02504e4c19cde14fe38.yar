rule sig_20161206_6b08880eaeabe02504e4c19cde14fe38 {
  meta:
    description = "datamaliciousorder - file 20161206_6b08880eaeabe02504e4c19cde14fe38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c028dae50e81fb6ca9a5d0e6f9bc446de52042381af81c95c7536deabd91bb9"

  strings:
    $s1 = "var vYIz2 = new Function(\"s\", '{var vTp7 = new Date();vTp7[\"setUTCFullYear\"](\"2003\");if (vTp7.getUTCFullYear().toString(10" ascii
    $s2 = "var vYIz2 = new Function(\"s\", '{var vTp7 = new Date();vTp7[\"setUTCFullYear\"](\"2003\");if (vTp7.getUTCFullYear().toString(10" ascii
    $s3 = "function vQRa1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vIRh0 = s.split(\"##\"); return vIRh0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}