rule sig_20161207_41f0a7bb1d500f9f8dbb11a4dcaeaec8 {
  meta:
    description = "datamaliciousorder - file 20161207_41f0a7bb1d500f9f8dbb11a4dcaeaec8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a334259e5814b9b8a2dc6fad539dd1be3bb1b63bad257bfbe9d6b54510761ac"

  strings:
    $s1 = "var vVb2 = new Function(\"vZSm7\", '{return vZSm7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJJd8 = new Function(\"vZS" ascii
    $s2 = "5 = new Date();vSCi5[\"setUTCFullYear\"](\"2003\");if (vSCi5.getUTCFullYear().toString(10) == \"2003\") {var vGUj7 = vZSm7.split" ascii
    $s3 = "var vVb2 = new Function(\"vZSm7\", '{return vZSm7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJJd8 = new Function(\"vZS" ascii
    $s4 = "\"); return vGUj7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}