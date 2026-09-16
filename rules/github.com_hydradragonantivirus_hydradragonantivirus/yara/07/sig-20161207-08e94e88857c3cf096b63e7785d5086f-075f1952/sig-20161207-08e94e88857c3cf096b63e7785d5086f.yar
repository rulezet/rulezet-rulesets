rule sig_20161207_08e94e88857c3cf096b63e7785d5086f {
  meta:
    description = "datamaliciousorder - file 20161207_08e94e88857c3cf096b63e7785d5086f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22cf4874f4b268c87aa076f9b7bb065c62afc19dc35f16579614921f7dfd7b71"

  strings:
    $s1 = "var vMp8 = new Function(\"vZSq9\", '{return vZSq9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQUm3 = new Function(\"vZS" ascii
    $s2 = " = new Date();vIv2[\"setUTCFullYear\"](\"2003\");if (vIv2.getUTCFullYear().toString(10) == \"2003\") {var vAAr7 = vZSq9.split(\"" ascii
    $s3 = "var vMp8 = new Function(\"vZSq9\", '{return vZSq9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQUm3 = new Function(\"vZS" ascii
    $s4 = " return vAAr7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}