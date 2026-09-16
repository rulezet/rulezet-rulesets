rule sig_20161208_b51abb5be4734cc47d79321ab42bac14 {
  meta:
    description = "datamaliciousorder - file 20161208_b51abb5be4734cc47d79321ab42bac14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858ef9b414afeb8d192fd4b6de4372e940616f323ae184f83f7c0be11e91cb6d"

  strings:
    $s1 = " = new Date();vDo9[\"setUTC\"+\"FullYear\"](\"2003\");if (vDo9.getUTCFullYear().toString(10) == \"2003\") {var vHf9 = vEYc4.spli" ascii
    $s2 = "var vOq8 = new Function(\"vEYc4\", '{return vEYc4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYZi2 = new Function(\"vEY" ascii
    $s3 = "); return vHf9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vOq8 = new Function(\"vEYc4\", '{return vEYc4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYZi2 = new Function(\"vEY" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}