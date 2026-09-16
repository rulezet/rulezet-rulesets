rule sig_20161208_5e23b9ac697aa127bba8603e1345c675 {
  meta:
    description = "datamaliciousorder - file 20161208_5e23b9ac697aa127bba8603e1345c675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "823058785942fc54be5f1f623efb97ed787fe026070ea98e6567798600ccf5bc"

  strings:
    $s1 = "var vVVb2 = new Function(\"vTz3\", '{return vTz3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCf9 = new Function(\"vTz3" ascii
    $s2 = "new Date();vDj6[\"setUTC\"+\"FullYear\"](\"2003\");if (vDj6.getUTCFullYear().toString(10) == \"2003\") {var vNb4 = vTz3.split(\"" ascii
    $s3 = "eturn vNb4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVVb2 = new Function(\"vTz3\", '{return vTz3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCf9 = new Function(\"vTz3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}