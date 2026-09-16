rule sig_20161207_f181c0d4a64b2ba2fe5d4201bf19512b {
  meta:
    description = "datamaliciousorder - file 20161207_f181c0d4a64b2ba2fe5d4201bf19512b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72d0dc0ebbc6c2e3ab22055ad84ffaedc574f75284a0c62152b73f1fcefffb38"

  strings:
    $s1 = " new Date();vCUf4[\"setUTCFullYear\"](\"2003\");if (vCUf4.getUTCFullYear().toString(10) == \"2003\") {var vOh4 = vKt5.split(\"##" ascii
    $s2 = "var vAa5 = new Function(\"vKt5\", '{return vKt5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDNy3 = new Function(\"vKt5" ascii
    $s3 = "var vAa5 = new Function(\"vKt5\", '{return vKt5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDNy3 = new Function(\"vKt5" ascii
    $s4 = "eturn vOh4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}