rule sig_20161207_37cd3d89cda4cc3470fbdece1f08dc1a {
  meta:
    description = "datamaliciousorder - file 20161207_37cd3d89cda4cc3470fbdece1f08dc1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35568b14b6edf89c7158e668baff3cfff1cc6065d57103206803c7ca50f674df"

  strings:
    $s1 = "var vAm4 = new Function(\"vWf9\", '{var vVZh7 = new Date();vVZh7[\"setUTCFullYear\"](\"2003\");if (vVZh7.getUTCFullYear().toStri" ascii
    $s2 = "var vAm4 = new Function(\"vWf9\", '{var vVZh7 = new Date();vVZh7[\"setUTCFullYear\"](\"2003\");if (vVZh7.getUTCFullYear().toStri" ascii
    $s3 = "var vNGt3 = new Function(\"vWf9\", '{return vWf9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vDn6 = vWf9.split(\"###\"); return vDn6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}