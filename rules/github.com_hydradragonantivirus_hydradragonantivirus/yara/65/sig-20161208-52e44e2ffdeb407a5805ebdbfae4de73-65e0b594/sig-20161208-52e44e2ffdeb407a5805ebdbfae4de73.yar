rule sig_20161208_52e44e2ffdeb407a5805ebdbfae4de73 {
  meta:
    description = "datamaliciousorder - file 20161208_52e44e2ffdeb407a5805ebdbfae4de73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8c028057bf23cbf2f6fbd96da234697457415346fd6173c3adfab4f60d3cc3a"

  strings:
    $s1 = "b4 = new Date();vDGb4[\"setUTC\"+\"FullYear\"](\"2003\");if (vDGb4.getUTCFullYear().toString(10) == \"2003\") {var vYMh7 = vERt0" ascii
    $s2 = "var vBGp0 = new Function(\"vERt0\", '{return vERt0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOZk3 = new Function(\"vE" ascii
    $s3 = "var vBGp0 = new Function(\"vERt0\", '{return vERt0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOZk3 = new Function(\"vE" ascii
    $s4 = "####\"); return vYMh7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}