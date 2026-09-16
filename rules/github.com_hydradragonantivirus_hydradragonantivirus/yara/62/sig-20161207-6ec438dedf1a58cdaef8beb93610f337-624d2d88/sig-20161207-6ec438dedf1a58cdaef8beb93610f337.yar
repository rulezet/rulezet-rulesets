rule sig_20161207_6ec438dedf1a58cdaef8beb93610f337 {
  meta:
    description = "datamaliciousorder - file 20161207_6ec438dedf1a58cdaef8beb93610f337.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2100b8d872d81a9bf8fabb9bcc85cf38868c7497fd07640184df8aea6c7beb0"

  strings:
    $s1 = "ew Date();vPf9[\"setUTCFullYear\"](\"2003\");if (vPf9.getUTCFullYear().toString(10) == \"2003\") {var vMCm4 = vPd8.split(\"####" ascii
    $s2 = "var vOv4 = new Function(\"vPd8\", '{return vPd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZh8 = new Function(\"vPd8\"" ascii
    $s3 = "var vOv4 = new Function(\"vPd8\", '{return vPd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZh8 = new Function(\"vPd8\"" ascii
    $s4 = "rn vMCm4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}