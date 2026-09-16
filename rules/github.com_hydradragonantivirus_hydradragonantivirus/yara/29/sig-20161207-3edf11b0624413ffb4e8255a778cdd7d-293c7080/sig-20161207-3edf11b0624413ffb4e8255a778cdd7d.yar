rule sig_20161207_3edf11b0624413ffb4e8255a778cdd7d {
  meta:
    description = "datamaliciousorder - file 20161207_3edf11b0624413ffb4e8255a778cdd7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a041dc92f09622859222a178231f24e89df58a6204712cf3c14ec6e7f668d36f"

  strings:
    $s1 = "var vZd6 = new Function(\"vTf4\", '{return vTf4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIf2 = new Function(\"vTf4\"" ascii
    $s2 = "ew Date();vXd3[\"setUTCFullYear\"](\"2003\");if (vXd3.getUTCFullYear().toString(10) == \"2003\") {var vFJr0 = vTf4.split(\"####" ascii
    $s3 = "var vZd6 = new Function(\"vTf4\", '{return vTf4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIf2 = new Function(\"vTf4\"" ascii
    $s4 = "rn vFJr0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}