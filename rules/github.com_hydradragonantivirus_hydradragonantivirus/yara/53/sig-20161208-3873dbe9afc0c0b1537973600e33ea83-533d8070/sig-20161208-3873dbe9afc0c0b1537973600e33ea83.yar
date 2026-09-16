rule sig_20161208_3873dbe9afc0c0b1537973600e33ea83 {
  meta:
    description = "datamaliciousorder - file 20161208_3873dbe9afc0c0b1537973600e33ea83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34011ba440d4ee7f8048d3ad84251cd2fee00082fad20c212fbf936d9b25adbf"

  strings:
    $s1 = "new Date();vKCc0[\"setUTC\"+\"FullYear\"](\"2003\");if (vKCc0.getUTCFullYear().toString(10) == \"2003\") {var vCZu2 = vIa2.split" ascii
    $s2 = "var vEh5 = new Function(\"vIa2\", '{return vIa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEt9 = new Function(\"vIa2\"" ascii
    $s3 = "var vEh5 = new Function(\"vIa2\", '{return vIa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEt9 = new Function(\"vIa2\"" ascii
    $s4 = "; return vCZu2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}