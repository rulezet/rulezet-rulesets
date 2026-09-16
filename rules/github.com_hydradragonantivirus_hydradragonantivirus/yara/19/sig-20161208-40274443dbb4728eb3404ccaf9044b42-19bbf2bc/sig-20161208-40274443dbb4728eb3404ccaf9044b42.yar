rule sig_20161208_40274443dbb4728eb3404ccaf9044b42 {
  meta:
    description = "datamaliciousorder - file 20161208_40274443dbb4728eb3404ccaf9044b42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "500d00bec97a2ea8c8e8513acdbd50aae7ad6f818d0af69630c15c705c4b7da0"

  strings:
    $s1 = " new Date();vGe5[\"setUTC\"+\"FullYear\"](\"2003\");if (vGe5.getUTCFullYear().toString(10) == \"2003\") {var vMSa3 = vMo3.split(" ascii
    $s2 = "var vXBh8 = new Function(\"vMo3\", '{return vMo3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDHu2 = new Function(\"vMo3" ascii
    $s3 = "var vXBh8 = new Function(\"vMo3\", '{return vMo3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDHu2 = new Function(\"vMo3" ascii
    $s4 = " return vMSa3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}