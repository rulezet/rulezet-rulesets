rule sig_20161207_fbbef3f98d344551701147294809459b {
  meta:
    description = "datamaliciousorder - file 20161207_fbbef3f98d344551701147294809459b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "895782131da411bda9c7a27788577a788d0af14de99a1327dd67c102836765cd"

  strings:
    $s1 = "var vLb3 = new Function(\"vLXz4\", '{return vLXz4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUf0 = new Function(\"vLXz" ascii
    $s2 = "= new Date();vQu4[\"setUTCFullYear\"](\"2003\");if (vQu4.getUTCFullYear().toString(10) == \"2003\") {var vYh7 = vLXz4.split(\"##" ascii
    $s3 = "var vLb3 = new Function(\"vLXz4\", '{return vLXz4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUf0 = new Function(\"vLXz" ascii
    $s4 = "eturn vYh7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}