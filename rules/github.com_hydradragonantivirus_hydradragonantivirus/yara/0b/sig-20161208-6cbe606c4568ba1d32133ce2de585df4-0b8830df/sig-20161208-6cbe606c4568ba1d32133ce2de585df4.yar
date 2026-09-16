rule sig_20161208_6cbe606c4568ba1d32133ce2de585df4 {
  meta:
    description = "datamaliciousorder - file 20161208_6cbe606c4568ba1d32133ce2de585df4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ad896e6b4cf369dc597d44db310414ab3b8ae3be2db0aa0427ca99551ae459a"

  strings:
    $s1 = "var vVIw7 = new Function(\"vUCc5\", '{return vUCc5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJMh2 = new Function(\"vU" ascii
    $s2 = "k4 = new Date();vLEk4[\"setUTC\"+\"FullYear\"](\"2003\");if (vLEk4.getUTCFullYear().toString(10) == \"2003\") {var vNVj1 = vUCc5" ascii
    $s3 = "####\"); return vNVj1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVIw7 = new Function(\"vUCc5\", '{return vUCc5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJMh2 = new Function(\"vU" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}