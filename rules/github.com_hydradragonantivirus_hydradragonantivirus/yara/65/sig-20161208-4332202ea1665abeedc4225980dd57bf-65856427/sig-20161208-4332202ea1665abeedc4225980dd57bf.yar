rule sig_20161208_4332202ea1665abeedc4225980dd57bf {
  meta:
    description = "datamaliciousorder - file 20161208_4332202ea1665abeedc4225980dd57bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57e567b4091ab6664f81295bcdce12e621da3ebb444e21e347e74bd6360735bd"

  strings:
    $s1 = " = new Date();vBc9[\"setUTC\"+\"FullYear\"](\"2003\");if (vBc9.getUTCFullYear().toString(10) == \"2003\") {var vLb4 = vDSm3.spli" ascii
    $s2 = "var vKQs2 = new Function(\"vDSm3\", '{return vDSm3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYl9 = new Function(\"vDS" ascii
    $s3 = "); return vLb4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKQs2 = new Function(\"vDSm3\", '{return vDSm3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYl9 = new Function(\"vDS" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}