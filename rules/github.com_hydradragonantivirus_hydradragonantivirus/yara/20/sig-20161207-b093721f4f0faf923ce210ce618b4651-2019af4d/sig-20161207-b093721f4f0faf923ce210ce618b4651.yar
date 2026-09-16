rule sig_20161207_b093721f4f0faf923ce210ce618b4651 {
  meta:
    description = "datamaliciousorder - file 20161207_b093721f4f0faf923ce210ce618b4651.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58652b79aa7a8568c9369f803126c0d3228eddf5583128f30296162e0765b69d"

  strings:
    $s1 = "m6 = new Date();vWFm6[\"setUTCFullYear\"](\"2003\");if (vWFm6.getUTCFullYear().toString(10) == \"2003\") {var vFIf9 = vNVj8.spli" ascii
    $s2 = "var vIIo4 = new Function(\"vNVj8\", '{return vNVj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEKv7 = new Function(\"vN" ascii
    $s3 = "#\"); return vFIf9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIIo4 = new Function(\"vNVj8\", '{return vNVj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEKv7 = new Function(\"vN" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}