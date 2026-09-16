rule sig_20161207_38311722bc65b4b28b597e237e1c2006 {
  meta:
    description = "datamaliciousorder - file 20161207_38311722bc65b4b28b597e237e1c2006.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "207317f36971519b88266920e735c471b17e8666dfa39c63e6f3a27bdc5c7068"

  strings:
    $s1 = "var vSm9 = new Function(\"vOu1\", '{return vOu1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHb3 = new Function(\"vOu1\"" ascii
    $s2 = "new Date();vHKw2[\"setUTCFullYear\"](\"2003\");if (vHKw2.getUTCFullYear().toString(10) == \"2003\") {var vBf7 = vOu1.split(\"###" ascii
    $s3 = "turn vBf7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSm9 = new Function(\"vOu1\", '{return vOu1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHb3 = new Function(\"vOu1\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}