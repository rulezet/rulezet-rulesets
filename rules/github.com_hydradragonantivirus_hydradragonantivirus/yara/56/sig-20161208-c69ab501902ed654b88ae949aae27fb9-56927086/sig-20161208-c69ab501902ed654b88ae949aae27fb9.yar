rule sig_20161208_c69ab501902ed654b88ae949aae27fb9 {
  meta:
    description = "datamaliciousorder - file 20161208_c69ab501902ed654b88ae949aae27fb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad4411b05658f766db73cc7c4fda1d51a52cae3754411fc28bd8f6a8abe2463d"

  strings:
    $s1 = "var vGFx7 = new Function(\"vVj2\", '{return vVj2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYk8 = new Function(\"vVj2" ascii
    $s2 = " new Date();vQGk7[\"setUTC\"+\"FullYear\"](\"2003\");if (vQGk7.getUTCFullYear().toString(10) == \"2003\") {var vXZb0 = vVj2.spli" ascii
    $s3 = "); return vXZb0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGFx7 = new Function(\"vVj2\", '{return vVj2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYk8 = new Function(\"vVj2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}