rule sig_20161208_57cb2f1002ac21f77c285a271a5b1eac {
  meta:
    description = "datamaliciousorder - file 20161208_57cb2f1002ac21f77c285a271a5b1eac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c7ec18557d2bea4ac675ac977e3698e4f87dcd78127aa06ace8c34c202a73a0"

  strings:
    $s1 = "var vWRb6 = new Function(\"vNy4\", '{return vNy4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVw1 = new Function(\"vNy4" ascii
    $s2 = " new Date();vTFz1[\"setUTC\"+\"FullYear\"](\"2003\");if (vTFz1.getUTCFullYear().toString(10) == \"2003\") {var vXCk4 = vNy4.spli" ascii
    $s3 = "); return vXCk4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWRb6 = new Function(\"vNy4\", '{return vNy4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVw1 = new Function(\"vNy4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}