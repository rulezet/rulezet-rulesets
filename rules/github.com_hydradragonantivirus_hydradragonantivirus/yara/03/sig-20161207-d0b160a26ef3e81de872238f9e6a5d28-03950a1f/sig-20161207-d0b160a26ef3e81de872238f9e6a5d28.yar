rule sig_20161207_d0b160a26ef3e81de872238f9e6a5d28 {
  meta:
    description = "datamaliciousorder - file 20161207_d0b160a26ef3e81de872238f9e6a5d28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b57fa20bdc45db006e9de2235c02ae3608454908492b1e8fbdb0a29651fa3076"

  strings:
    $s1 = "= new Date();vIu9[\"setUTCFullYear\"](\"2003\");if (vIu9.getUTCFullYear().toString(10) == \"2003\") {var vSa9 = vJOo0.split(\"##" ascii
    $s2 = "var vQb8 = new Function(\"vJOo0\", '{return vJOo0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWa4 = new Function(\"vJOo" ascii
    $s3 = "eturn vSa9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQb8 = new Function(\"vJOo0\", '{return vJOo0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWa4 = new Function(\"vJOo" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}