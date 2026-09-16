rule sig_20161207_66b569b3c1bba9d15f1c3690a5df9d14 {
  meta:
    description = "datamaliciousorder - file 20161207_66b569b3c1bba9d15f1c3690a5df9d14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31fac4812544ce502a61eed24ae9d7be57cbbbe45c5423faf625fa9cf5941d53"

  strings:
    $s1 = "var vHTg2 = new Function(\"vNZz3\", '{var vWt2 = new Date();vWt2[\"setUTCFullYear\"](\"2003\");if (vWt2.getUTCFullYear().toStrin" ascii
    $s2 = "var vHTg2 = new Function(\"vNZz3\", '{var vWt2 = new Date();vWt2[\"setUTCFullYear\"](\"2003\");if (vWt2.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vXk9 = vNZz3.split(\"###\"); return vXk9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vPUl3 = new Function(\"vNZz3\", '{return vNZz3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}