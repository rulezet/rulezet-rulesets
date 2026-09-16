rule sig_20161207_d8b42df4a77e4d733e28ca1baaa1f1ca {
  meta:
    description = "datamaliciousorder - file 20161207_d8b42df4a77e4d733e28ca1baaa1f1ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a1cada246b824098e28935fd9c7788a15f1b0a763cb3e72d4a4b71ceb69e505"

  strings:
    $s1 = "var vEYv8 = new Function(\"vNr9\", '{var vXAl1 = new Date();vXAl1[\"setUTCFullYear\"](\"2003\");if (vXAl1.getUTCFullYear().toStr" ascii
    $s2 = "var vEYv8 = new Function(\"vNr9\", '{var vXAl1 = new Date();vXAl1[\"setUTCFullYear\"](\"2003\");if (vXAl1.getUTCFullYear().toStr" ascii
    $s3 = "var vZx5 = new Function(\"vNr9\", '{return vNr9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vPg0 = vNr9.split(\"###\"); return vPg0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}