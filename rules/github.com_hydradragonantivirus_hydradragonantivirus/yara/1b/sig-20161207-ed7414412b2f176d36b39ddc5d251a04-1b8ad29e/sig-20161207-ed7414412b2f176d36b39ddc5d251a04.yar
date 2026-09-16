rule sig_20161207_ed7414412b2f176d36b39ddc5d251a04 {
  meta:
    description = "datamaliciousorder - file 20161207_ed7414412b2f176d36b39ddc5d251a04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccd07a9c5483fb4376ecf98d44efce9ffbb5ede6e4ac7006de5d4c81562664a7"

  strings:
    $s1 = " = new Date();vQm6[\"setUTCFullYear\"](\"2003\");if (vQm6.getUTCFullYear().toString(10) == \"2003\") {var vQKw5 = vROn1.split(\"" ascii
    $s2 = "var vQHm8 = new Function(\"vROn1\", '{return vROn1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYb2 = new Function(\"vRO" ascii
    $s3 = " return vQKw5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQHm8 = new Function(\"vROn1\", '{return vROn1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYb2 = new Function(\"vRO" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}