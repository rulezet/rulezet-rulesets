rule sig_20161208_633eef3fb68e26a9ba3c4015a1a9de94 {
  meta:
    description = "datamaliciousorder - file 20161208_633eef3fb68e26a9ba3c4015a1a9de94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7eed95db7696fb617e838155b8e04de9e7c5cb89709134cc19c6855d20af0f5c"

  strings:
    $s1 = "0 = new Date();vUv0[\"setUTC\"+\"FullYear\"](\"2003\");if (vUv0.getUTCFullYear().toString(10) == \"2003\") {var vIf0 = vQYh4.spl" ascii
    $s2 = "var vBXi3 = new Function(\"vQYh4\", '{return vQYh4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMOt5 = new Function(\"vQ" ascii
    $s3 = "\"); return vIf0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBXi3 = new Function(\"vQYh4\", '{return vQYh4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMOt5 = new Function(\"vQ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}