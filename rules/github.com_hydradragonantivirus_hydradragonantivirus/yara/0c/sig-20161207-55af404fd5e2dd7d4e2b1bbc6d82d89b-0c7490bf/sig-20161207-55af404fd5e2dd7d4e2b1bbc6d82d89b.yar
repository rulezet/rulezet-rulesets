rule sig_20161207_55af404fd5e2dd7d4e2b1bbc6d82d89b {
  meta:
    description = "datamaliciousorder - file 20161207_55af404fd5e2dd7d4e2b1bbc6d82d89b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7fb46abaabc09c0c7c877bfa207ff25b3575547e510c058294b57e5b37edd7d"

  strings:
    $s1 = "= new Date();vVVr9[\"setUTCFullYear\"](\"2003\");if (vVVr9.getUTCFullYear().toString(10) == \"2003\") {var vXm7 = vQu3.split(\"#" ascii
    $s2 = "var vGSm3 = new Function(\"vQu3\", '{return vQu3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZLh1 = new Function(\"vQu3" ascii
    $s3 = "var vGSm3 = new Function(\"vQu3\", '{return vQu3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZLh1 = new Function(\"vQu3" ascii
    $s4 = "return vXm7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}