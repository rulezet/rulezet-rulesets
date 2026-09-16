rule sig_20161207_e5ea5da2527099806373b4034ddd35aa {
  meta:
    description = "datamaliciousorder - file 20161207_e5ea5da2527099806373b4034ddd35aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed7d0f4c3b88f616fd2f3a5f4b329f46a96725c75a4e35a831ce26b0c240bfe1"

  strings:
    $s1 = "var vTv0 = new Function(\"vNf4\", '{var vJOl1 = new Date();vJOl1[\"setUTCFullYear\"](\"2003\");if (vJOl1.getUTCFullYear().toStri" ascii
    $s2 = "var vTv0 = new Function(\"vNf4\", '{var vJOl1 = new Date();vJOl1[\"setUTCFullYear\"](\"2003\");if (vJOl1.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vZr8 = vNf4.split(\"###\"); return vZr8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vPTg5 = new Function(\"vNf4\", '{return vNf4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}