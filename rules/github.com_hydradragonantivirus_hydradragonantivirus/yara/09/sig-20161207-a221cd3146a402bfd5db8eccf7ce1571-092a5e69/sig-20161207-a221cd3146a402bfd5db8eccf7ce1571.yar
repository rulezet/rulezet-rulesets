rule sig_20161207_a221cd3146a402bfd5db8eccf7ce1571 {
  meta:
    description = "datamaliciousorder - file 20161207_a221cd3146a402bfd5db8eccf7ce1571.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfedee10cee9e06e17dd00bd3214ef990846d4aa7ff81c075e134476caa2acb3"

  strings:
    $s1 = "new Date();vKq9[\"setUTCFullYear\"](\"2003\");if (vKq9.getUTCFullYear().toString(10) == \"2003\") {var vXCd6 = vXj8.split(\"####" ascii
    $s2 = "var vVMq1 = new Function(\"vXj8\", '{return vXj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMd6 = new Function(\"vXj8" ascii
    $s3 = "var vVMq1 = new Function(\"vXj8\", '{return vXj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMd6 = new Function(\"vXj8" ascii
    $s4 = "urn vXCd6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}