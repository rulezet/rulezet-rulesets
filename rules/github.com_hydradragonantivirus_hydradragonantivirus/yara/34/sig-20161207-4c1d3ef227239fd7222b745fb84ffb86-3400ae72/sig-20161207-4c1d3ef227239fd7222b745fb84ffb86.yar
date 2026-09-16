rule sig_20161207_4c1d3ef227239fd7222b745fb84ffb86 {
  meta:
    description = "datamaliciousorder - file 20161207_4c1d3ef227239fd7222b745fb84ffb86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8e00fe19af1970c857ec0e7b33c950fd590aca62ed736b9c9294b4e39f1a65b"

  strings:
    $s1 = "var vMs8 = new Function(\"vXy7\", '{var vQl2 = new Date();vQl2[\"setUTCFullYear\"](\"2003\");if (vQl2.getUTCFullYear().toString(" ascii
    $s2 = "var vMs8 = new Function(\"vXy7\", '{var vQl2 = new Date();vQl2[\"setUTCFullYear\"](\"2003\");if (vQl2.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vFUg9 = vXy7.split(\"###\"); return vFUg9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCo1 = new Function(\"vXy7\", '{return vXy7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}