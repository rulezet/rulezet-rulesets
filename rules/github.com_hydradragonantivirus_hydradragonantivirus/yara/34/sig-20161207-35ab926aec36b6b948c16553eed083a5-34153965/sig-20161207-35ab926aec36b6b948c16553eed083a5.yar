rule sig_20161207_35ab926aec36b6b948c16553eed083a5 {
  meta:
    description = "datamaliciousorder - file 20161207_35ab926aec36b6b948c16553eed083a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44e9764fc4d192d4f91e5d717b3a67e4acfcbabde3019ed783036d47a6c0e10a"

  strings:
    $s1 = "var vNCm9 = new Function(\"vCPa2\", '{return vCPa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDn4 = new Function(\"vCP" ascii
    $s2 = "1 = new Date();vREf1[\"setUTCFullYear\"](\"2003\");if (vREf1.getUTCFullYear().toString(10) == \"2003\") {var vULj3 = vCPa2.split" ascii
    $s3 = "\"); return vULj3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNCm9 = new Function(\"vCPa2\", '{return vCPa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDn4 = new Function(\"vCP" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}