rule sig_20161207_19632e8f504e23809dce7d6afa27d3f7 {
  meta:
    description = "datamaliciousorder - file 20161207_19632e8f504e23809dce7d6afa27d3f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c1df41e4e554ccdd87b3eb1aa4b4d1028ddef3d26b57b97df6bca967dd12ac7"

  strings:
    $s1 = " new Date();vJh9[\"setUTCFullYear\"](\"2003\");if (vJh9.getUTCFullYear().toString(10) == \"2003\") {var vWNe6 = vQx8.split(\"###" ascii
    $s2 = "var vKOw1 = new Function(\"vQx8\", '{return vQx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vREz0 = new Function(\"vQx8" ascii
    $s3 = "var vKOw1 = new Function(\"vQx8\", '{return vQx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vREz0 = new Function(\"vQx8" ascii
    $s4 = "turn vWNe6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}