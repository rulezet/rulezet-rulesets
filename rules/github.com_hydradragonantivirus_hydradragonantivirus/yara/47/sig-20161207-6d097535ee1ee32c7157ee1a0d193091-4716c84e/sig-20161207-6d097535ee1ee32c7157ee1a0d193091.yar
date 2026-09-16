rule sig_20161207_6d097535ee1ee32c7157ee1a0d193091 {
  meta:
    description = "datamaliciousorder - file 20161207_6d097535ee1ee32c7157ee1a0d193091.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b350b7e9218463edd9103ea8a6a1f1dc371aa544786d3cb476c02cb1f5a5b186"

  strings:
    $s1 = "var vJLe2 = new Function(\"vMa7\", '{var vAg0 = new Date();vAg0[\"setUTCFullYear\"](\"2003\");if (vAg0.getUTCFullYear().toString" ascii
    $s2 = "var vJLe2 = new Function(\"vMa7\", '{var vAg0 = new Date();vAg0[\"setUTCFullYear\"](\"2003\");if (vAg0.getUTCFullYear().toString" ascii
    $s3 = "var vUBv4 = new Function(\"vMa7\", '{return vMa7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vYt7 = vMa7.split(\"###\"); return vYt7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}