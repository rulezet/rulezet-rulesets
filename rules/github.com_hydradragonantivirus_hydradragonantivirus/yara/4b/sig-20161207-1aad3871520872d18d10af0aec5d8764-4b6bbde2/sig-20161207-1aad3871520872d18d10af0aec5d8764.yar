rule sig_20161207_1aad3871520872d18d10af0aec5d8764 {
  meta:
    description = "datamaliciousorder - file 20161207_1aad3871520872d18d10af0aec5d8764.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "744125af9bb7648f9122003cbd6a751c8ce9ee9611c2dfb98b212b70c54d8e8a"

  strings:
    $s1 = "var vLDr8 = new Function(\"vTz0\", '{var vYp7 = new Date();vYp7[\"setUTCFullYear\"](\"2003\");if (vYp7.getUTCFullYear().toString" ascii
    $s2 = "var vLDr8 = new Function(\"vTz0\", '{var vYp7 = new Date();vYp7[\"setUTCFullYear\"](\"2003\");if (vYp7.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vCEx1 = vTz0.split(\"###\"); return vCEx1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vLUy0 = new Function(\"vTz0\", '{return vTz0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}