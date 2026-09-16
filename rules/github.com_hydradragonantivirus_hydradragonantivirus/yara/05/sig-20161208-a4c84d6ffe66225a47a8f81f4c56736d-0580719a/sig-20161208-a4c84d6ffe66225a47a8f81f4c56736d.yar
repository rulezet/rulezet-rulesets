rule sig_20161208_a4c84d6ffe66225a47a8f81f4c56736d {
  meta:
    description = "datamaliciousorder - file 20161208_a4c84d6ffe66225a47a8f81f4c56736d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "220faeda8af0c096b7a7fa19bcae24abda1f9ab9e8fc469fc801a3d095127a1f"

  strings:
    $s1 = " new Date();vQKw4[\"setUTC\"+\"FullYear\"](\"2003\");if (vQKw4.getUTCFullYear().toString(10) == \"2003\") {var vUIq9 = vKm5.spli" ascii
    $s2 = "var vOh8 = new Function(\"vKm5\", '{return vKm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQKm7 = new Function(\"vKm5" ascii
    $s3 = "var vOh8 = new Function(\"vKm5\", '{return vKm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQKm7 = new Function(\"vKm5" ascii
    $s4 = "); return vUIq9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}