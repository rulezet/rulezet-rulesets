rule sig_20161207_a2043ccff4928e9c4ec26ec297c8c092 {
  meta:
    description = "datamaliciousorder - file 20161207_a2043ccff4928e9c4ec26ec297c8c092.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "136f21ca75e9ee33db97e3178ad9141279f90f28b468f43a6e0d195f54a4a7da"

  strings:
    $s1 = "var vYj8 = new Function(\"vRu0\", '{var vBc6 = new Date();vBc6[\"setUTCFullYear\"](\"2003\");if (vBc6.getUTCFullYear().toString(" ascii
    $s2 = "var vYj8 = new Function(\"vRu0\", '{var vBc6 = new Date();vBc6[\"setUTCFullYear\"](\"2003\");if (vBc6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vWg0 = vRu0.split(\"###\"); return vWg0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vZr2 = new Function(\"vRu0\", '{return vRu0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}