rule sig_20161207_2aae92577ce9b3ece4d8c5d1804392b3 {
  meta:
    description = "datamaliciousorder - file 20161207_2aae92577ce9b3ece4d8c5d1804392b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6307afe7b214bea1f2fa43f530a7b59b6602879abbc6fb3c3de3f3b3c988ced4"

  strings:
    $s1 = "var vPXd5 = new Function(\"vSFb1\", '{var vSa9 = new Date();vSa9[\"setUTCFullYear\"](\"2003\");if (vSa9.getUTCFullYear().toStrin" ascii
    $s2 = "var vPXd5 = new Function(\"vSFb1\", '{var vSa9 = new Date();vSa9[\"setUTCFullYear\"](\"2003\");if (vSa9.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vFi9 = vSFb1.split(\"###\"); return vFi9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vFu1 = new Function(\"vSFb1\", '{return vSFb1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}