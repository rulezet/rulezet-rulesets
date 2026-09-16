rule sig_20161208_e1eac4fff3eb74b4e38888d28c219f6c {
  meta:
    description = "datamaliciousorder - file 20161208_e1eac4fff3eb74b4e38888d28c219f6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7361734bae82c7b9afa52a684b7c9dce01b7ec2243af0358afac5034c09f0be9"

  strings:
    $s1 = "6 = new Date();vFSs6[\"setUTC\"+\"FullYear\"](\"2003\");if (vFSs6.getUTCFullYear().toString(10) == \"2003\") {var vBk8 = vACb0.s" ascii
    $s2 = "var vDk3 = new Function(\"vACb0\", '{return vACb0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGNb8 = new Function(\"vAC" ascii
    $s3 = "var vDk3 = new Function(\"vACb0\", '{return vACb0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGNb8 = new Function(\"vAC" ascii
    $s4 = "##\"); return vBk8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}