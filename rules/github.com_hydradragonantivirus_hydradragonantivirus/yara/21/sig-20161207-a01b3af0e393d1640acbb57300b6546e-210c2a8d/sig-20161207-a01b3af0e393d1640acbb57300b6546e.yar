rule sig_20161207_a01b3af0e393d1640acbb57300b6546e {
  meta:
    description = "datamaliciousorder - file 20161207_a01b3af0e393d1640acbb57300b6546e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75acecdaacabbb492d7df414608d8a90cc9d099fefe3154c734f2d7a76621838"

  strings:
    $s1 = "var vOf7 = new Function(\"vZAc0\", '{var vKu9 = new Date();vKu9[\"setUTCFullYear\"](\"2003\");if (vKu9.getUTCFullYear().toString" ascii
    $s2 = "var vOf7 = new Function(\"vZAc0\", '{var vKu9 = new Date();vKu9[\"setUTCFullYear\"](\"2003\");if (vKu9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vDSv9 = vZAc0.split(\"###\"); return vDSv9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWKy4 = new Function(\"vZAc0\", '{return vZAc0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}