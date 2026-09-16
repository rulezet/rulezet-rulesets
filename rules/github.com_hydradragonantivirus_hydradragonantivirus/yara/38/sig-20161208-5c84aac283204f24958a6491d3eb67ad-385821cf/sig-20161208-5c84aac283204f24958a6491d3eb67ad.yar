rule sig_20161208_5c84aac283204f24958a6491d3eb67ad {
  meta:
    description = "datamaliciousorder - file 20161208_5c84aac283204f24958a6491d3eb67ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b14d464c0a626c4ba5adcbd4db6c2274a23e8b695e50fd0cd3dad683ac480ff7"

  strings:
    $s1 = "= new Date();vNt7[\"setUTC\"+\"FullYear\"](\"2003\");if (vNt7.getUTCFullYear().toString(10) == \"2003\") {var vKj7 = vFFm5.split" ascii
    $s2 = "var vUi6 = new Function(\"vFFm5\", '{return vFFm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUs3 = new Function(\"vFFm" ascii
    $s3 = "; return vKj7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUi6 = new Function(\"vFFm5\", '{return vFFm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUs3 = new Function(\"vFFm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}