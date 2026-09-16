rule sig_20161208_637f0e437cefbbc70265296868f1f80a {
  meta:
    description = "datamaliciousorder - file 20161208_637f0e437cefbbc70265296868f1f80a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee39e4780549cfab35a6331919e82803603932608962dcdeca0dcf1578580b48"

  strings:
    $s1 = "= new Date();vAv9[\"setUTC\"+\"FullYear\"](\"2003\");if (vAv9.getUTCFullYear().toString(10) == \"2003\") {var vKIk2 = vGIu8.spli" ascii
    $s2 = "var vIb8 = new Function(\"vGIu8\", '{return vGIu8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMs1 = new Function(\"vGIu" ascii
    $s3 = "); return vKIk2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIb8 = new Function(\"vGIu8\", '{return vGIu8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMs1 = new Function(\"vGIu" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}