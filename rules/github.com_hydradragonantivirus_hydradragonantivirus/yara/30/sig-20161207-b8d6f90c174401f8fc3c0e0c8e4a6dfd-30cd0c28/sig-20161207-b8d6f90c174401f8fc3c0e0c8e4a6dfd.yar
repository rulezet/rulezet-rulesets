rule sig_20161207_b8d6f90c174401f8fc3c0e0c8e4a6dfd {
  meta:
    description = "datamaliciousorder - file 20161207_b8d6f90c174401f8fc3c0e0c8e4a6dfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e24386afa4c636b6227caf6103f0a4f996cefff504225994dc686f278a798c2"

  strings:
    $s1 = "var vPl1 = new Function(\"vVm2\", '{var vFTf9 = new Date();vFTf9[\"setUTCFullYear\"](\"2003\");if (vFTf9.getUTCFullYear().toStri" ascii
    $s2 = "var vPl1 = new Function(\"vVm2\", '{var vFTf9 = new Date();vFTf9[\"setUTCFullYear\"](\"2003\");if (vFTf9.getUTCFullYear().toStri" ascii
    $s3 = "var vAc9 = new Function(\"vVm2\", '{return vVm2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vVSp8 = vVm2.split(\"###\"); return vVSp8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}