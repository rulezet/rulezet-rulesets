rule sig_20161207_69c8d379a6f8cd8e0c92052043043d8e {
  meta:
    description = "datamaliciousorder - file 20161207_69c8d379a6f8cd8e0c92052043043d8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c49f04e44e51da68b0bd7772c0250b08a60077bff2a9edc06abeab1001b20c3"

  strings:
    $s1 = "var vTi7 = new Function(\"vLQv7\", '{var vAn9 = new Date();vAn9[\"setUTCFullYear\"](\"2003\");if (vAn9.getUTCFullYear().toString" ascii
    $s2 = "var vTi7 = new Function(\"vLQv7\", '{var vAn9 = new Date();vAn9[\"setUTCFullYear\"](\"2003\");if (vAn9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vSIe0 = vLQv7.split(\"###\"); return vSIe0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBSm7 = new Function(\"vLQv7\", '{return vLQv7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}