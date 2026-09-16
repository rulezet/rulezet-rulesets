rule sig_20161208_8620321ab4e0a7c1e2be6d1d95d6a405 {
  meta:
    description = "datamaliciousorder - file 20161208_8620321ab4e0a7c1e2be6d1d95d6a405.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bedb44174c61b8dea9031cfc3aac325f2c40816383118274b3b3e23f00a60171"

  strings:
    $s1 = "ew Date();vVc1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVc1.getUTCFullYear().toString(10) == \"2003\") {var vYg7 = vFm1.split(\"#" ascii
    $s2 = "var vMx0 = new Function(\"vFm1\", '{return vFm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRm2 = new Function(\"vFm1\"" ascii
    $s3 = "var vMx0 = new Function(\"vFm1\", '{return vFm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRm2 = new Function(\"vFm1\"" ascii
    $s4 = "turn vYg7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}