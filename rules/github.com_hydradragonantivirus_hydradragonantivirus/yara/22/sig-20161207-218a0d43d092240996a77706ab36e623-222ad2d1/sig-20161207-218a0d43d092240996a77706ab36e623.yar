rule sig_20161207_218a0d43d092240996a77706ab36e623 {
  meta:
    description = "datamaliciousorder - file 20161207_218a0d43d092240996a77706ab36e623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c52bc843b6037f63c06aea63fce3025b84eec2412ee74ce44df1a80f427b9b71"

  strings:
    $s1 = "= new Date();vWXd2[\"setUTCFullYear\"](\"2003\");if (vWXd2.getUTCFullYear().toString(10) == \"2003\") {var vBPh4 = vIb4.split(\"" ascii
    $s2 = "var vDMh4 = new Function(\"vIb4\", '{return vIb4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIId0 = new Function(\"vIb4" ascii
    $s3 = " return vBPh4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDMh4 = new Function(\"vIb4\", '{return vIb4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIId0 = new Function(\"vIb4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}