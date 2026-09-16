rule sig_20161208_153fff5d9a3e9406ca005e48b35aba84 {
  meta:
    description = "datamaliciousorder - file 20161208_153fff5d9a3e9406ca005e48b35aba84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0036b7293a8f991843eacb8dcdd27a8e6715e8f7b5b8b66d0de2480b0aa83f6"

  strings:
    $s1 = "ew Date();vLa5[\"setUTC\"+\"FullYear\"](\"2003\");if (vLa5.getUTCFullYear().toString(10) == \"2003\") {var vBl3 = vOh1.split(\"#" ascii
    $s2 = "var vNa4 = new Function(\"vOh1\", '{return vOh1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSx9 = new Function(\"vOh1\"" ascii
    $s3 = "var vNa4 = new Function(\"vOh1\", '{return vOh1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSx9 = new Function(\"vOh1\"" ascii
    $s4 = "turn vBl3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}