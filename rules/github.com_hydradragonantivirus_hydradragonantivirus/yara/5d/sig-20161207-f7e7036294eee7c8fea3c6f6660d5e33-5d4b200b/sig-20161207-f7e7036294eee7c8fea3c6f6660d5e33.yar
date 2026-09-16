rule sig_20161207_f7e7036294eee7c8fea3c6f6660d5e33 {
  meta:
    description = "datamaliciousorder - file 20161207_f7e7036294eee7c8fea3c6f6660d5e33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea84741f8c1a770199f4bbb5b658897af6ef0e787609f420cbb10cb65e02b682"

  strings:
    $s1 = "var vFHz0 = new Function(\"vGRk9\", '{return vGRk9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUt9 = new Function(\"vGR" ascii
    $s2 = "4 = new Date();vNGe4[\"setUTCFullYear\"](\"2003\");if (vNGe4.getUTCFullYear().toString(10) == \"2003\") {var vPKz5 = vGRk9.split" ascii
    $s3 = "\"); return vPKz5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFHz0 = new Function(\"vGRk9\", '{return vGRk9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUt9 = new Function(\"vGR" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}