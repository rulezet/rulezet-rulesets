rule sig_20161208_5d5fa1cae6e9af07c9070f5a15b0734a {
  meta:
    description = "datamaliciousorder - file 20161208_5d5fa1cae6e9af07c9070f5a15b0734a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43705674a4fdc355ee5eacdf8b67caf0373d4d61dabd0c5e5fbd277b9d14234f"

  strings:
    $s1 = " = new Date();vLEp4[\"setUTC\"+\"FullYear\"](\"2003\");if (vLEp4.getUTCFullYear().toString(10) == \"2003\") {var vAEp8 = vYHk0.s" ascii
    $s2 = "var vUl7 = new Function(\"vYHk0\", '{return vYHk0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFw1 = new Function(\"vYHk" ascii
    $s3 = "var vUl7 = new Function(\"vYHk0\", '{return vYHk0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFw1 = new Function(\"vYHk" ascii
    $s4 = "##\"); return vAEp8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}