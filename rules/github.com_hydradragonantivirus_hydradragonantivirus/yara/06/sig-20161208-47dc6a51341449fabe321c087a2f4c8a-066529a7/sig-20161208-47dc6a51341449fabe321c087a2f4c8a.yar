rule sig_20161208_47dc6a51341449fabe321c087a2f4c8a {
  meta:
    description = "datamaliciousorder - file 20161208_47dc6a51341449fabe321c087a2f4c8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "242ac198eb8be0ceb7532dd4c08f214441733ccde6a0a57ce0bd9768c40a9ce3"

  strings:
    $s1 = "var vBPv2 = new Function(\"vYHr0\", '{return vYHr0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCh4 = new Function(\"vYH" ascii
    $s2 = " = new Date();vIq0[\"setUTC\"+\"FullYear\"](\"2003\");if (vIq0.getUTCFullYear().toString(10) == \"2003\") {var vFAt2 = vYHr0.spl" ascii
    $s3 = "\"); return vFAt2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBPv2 = new Function(\"vYHr0\", '{return vYHr0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCh4 = new Function(\"vYH" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}