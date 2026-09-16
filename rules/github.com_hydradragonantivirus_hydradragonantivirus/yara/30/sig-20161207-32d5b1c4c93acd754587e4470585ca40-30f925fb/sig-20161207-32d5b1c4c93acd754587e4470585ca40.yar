rule sig_20161207_32d5b1c4c93acd754587e4470585ca40 {
  meta:
    description = "datamaliciousorder - file 20161207_32d5b1c4c93acd754587e4470585ca40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4368a232c3843ebb33b1e3a9b240c3f4a0534a3b412bb5c7a0f7f0b90e45242f"

  strings:
    $s1 = "c4 = new Date();vVOc4[\"setUTCFullYear\"](\"2003\");if (vVOc4.getUTCFullYear().toString(10) == \"2003\") {var vDBe8 = vLYp7.spli" ascii
    $s2 = "var vQDl7 = new Function(\"vLYp7\", '{return vLYp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRNz0 = new Function(\"vL" ascii
    $s3 = "var vQDl7 = new Function(\"vLYp7\", '{return vLYp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRNz0 = new Function(\"vL" ascii
    $s4 = "#\"); return vDBe8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}