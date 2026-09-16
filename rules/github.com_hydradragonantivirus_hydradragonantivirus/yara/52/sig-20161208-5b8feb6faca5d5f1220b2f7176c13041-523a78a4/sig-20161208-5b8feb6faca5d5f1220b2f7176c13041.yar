rule sig_20161208_5b8feb6faca5d5f1220b2f7176c13041 {
  meta:
    description = "datamaliciousorder - file 20161208_5b8feb6faca5d5f1220b2f7176c13041.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c729465cc1ca4996ed716da7dc11656b1eca65f2cf458f742132be2f5fec0149"

  strings:
    $s1 = "var vMFu3 = new Function(\"vQVv6\", '{return vQVv6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZSa2 = new Function(\"vQ" ascii
    $s2 = "o2 = new Date();vKQo2[\"setUTC\"+\"FullYear\"](\"2003\");if (vKQo2.getUTCFullYear().toString(10) == \"2003\") {var vOg4 = vQVv6." ascii
    $s3 = "###\"); return vOg4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMFu3 = new Function(\"vQVv6\", '{return vQVv6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZSa2 = new Function(\"vQ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}