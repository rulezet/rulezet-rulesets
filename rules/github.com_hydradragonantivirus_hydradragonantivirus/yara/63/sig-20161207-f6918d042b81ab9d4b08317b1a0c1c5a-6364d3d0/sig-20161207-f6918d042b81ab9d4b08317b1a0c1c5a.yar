rule sig_20161207_f6918d042b81ab9d4b08317b1a0c1c5a {
  meta:
    description = "datamaliciousorder - file 20161207_f6918d042b81ab9d4b08317b1a0c1c5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfea88ae9fc01397aa56abb68ba59ea71a9414050621f92fc543aa53a98b961d"

  strings:
    $s1 = "var vHh1 = new Function(\"vIg8\", '{var vZb0 = new Date();vZb0[\"setUTCFullYear\"](\"2003\");if (vZb0.getUTCFullYear().toString(" ascii
    $s2 = "var vHh1 = new Function(\"vIg8\", '{var vZb0 = new Date();vZb0[\"setUTCFullYear\"](\"2003\");if (vZb0.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vYUs5 = vIg8.split(\"###\"); return vYUs5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vUf4 = new Function(\"vIg8\", '{return vIg8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}