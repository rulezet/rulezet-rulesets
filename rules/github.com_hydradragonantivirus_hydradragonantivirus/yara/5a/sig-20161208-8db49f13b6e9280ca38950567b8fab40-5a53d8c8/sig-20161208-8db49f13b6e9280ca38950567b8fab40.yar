rule sig_20161208_8db49f13b6e9280ca38950567b8fab40 {
  meta:
    description = "datamaliciousorder - file 20161208_8db49f13b6e9280ca38950567b8fab40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0e56ba7c2d19594040ab9651cd784e983a89e57e6376dd2ccc68e50bfe44c23"

  strings:
    $s1 = "var vBh1 = new Function(\"vGe9\", '{return vGe9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPCq7 = new Function(\"vGe9" ascii
    $s2 = " new Date();vFVi9[\"setUTC\"+\"FullYear\"](\"2003\");if (vFVi9.getUTCFullYear().toString(10) == \"2003\") {var vAPs4 = vGe9.spli" ascii
    $s3 = "); return vAPs4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBh1 = new Function(\"vGe9\", '{return vGe9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPCq7 = new Function(\"vGe9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}