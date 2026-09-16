rule sig_20161207_310fe81a9b1b1323a0c9416aec490358 {
  meta:
    description = "datamaliciousorder - file 20161207_310fe81a9b1b1323a0c9416aec490358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d66ae32b83199158f7a61a020c348f2843a6df203c31397a53658bb13e2c883f"

  strings:
    $s1 = "var vSXa8 = new Function(\"vUc9\", '{return vUc9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOJb9 = new Function(\"vUc9" ascii
    $s2 = "= new Date();vNHs0[\"setUTCFullYear\"](\"2003\");if (vNHs0.getUTCFullYear().toString(10) == \"2003\") {var vHBr8 = vUc9.split(\"" ascii
    $s3 = " return vHBr8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSXa8 = new Function(\"vUc9\", '{return vUc9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOJb9 = new Function(\"vUc9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}