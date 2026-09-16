rule sig_20161208_7d2e47a097ab77e99b19307a7a190296 {
  meta:
    description = "datamaliciousorder - file 20161208_7d2e47a097ab77e99b19307a7a190296.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e5ab0f40e87aae2bb32c5fc1b18bb3a942be1e2f08a32bcf30fcdd1a5971fcf"

  strings:
    $s1 = "new Date();vBf2[\"setUTC\"+\"FullYear\"](\"2003\");if (vBf2.getUTCFullYear().toString(10) == \"2003\") {var vEd7 = vUu8.split(\"" ascii
    $s2 = "var vTx0 = new Function(\"vUu8\", '{return vUu8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKNt5 = new Function(\"vUu8" ascii
    $s3 = "eturn vEd7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTx0 = new Function(\"vUu8\", '{return vUu8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKNt5 = new Function(\"vUu8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}