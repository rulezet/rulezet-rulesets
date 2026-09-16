rule sig_20161208_25ed872bb1179a0e03d4070f5719ab80 {
  meta:
    description = "datamaliciousorder - file 20161208_25ed872bb1179a0e03d4070f5719ab80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfd97eb12de6c9e01277b29d934bcb2191cf35ee74f5bce59919c8ae4f28f56"

  strings:
    $s1 = "var vBPa6 = new Function(\"vPTt0\", '{return vPTt0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYr4 = new Function(\"vPT" ascii
    $s2 = " = new Date();vRr6[\"setUTC\"+\"FullYear\"](\"2003\");if (vRr6.getUTCFullYear().toString(10) == \"2003\") {var vUUp2 = vPTt0.spl" ascii
    $s3 = "\"); return vUUp2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBPa6 = new Function(\"vPTt0\", '{return vPTt0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYr4 = new Function(\"vPT" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}