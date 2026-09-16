rule sig_20161207_c447c0454dc2c0c57e17a380e108e961 {
  meta:
    description = "datamaliciousorder - file 20161207_c447c0454dc2c0c57e17a380e108e961.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3d31a155409b8724bc51df00dbee479f13a2981f359ce9b1cf705c29db61dfe"

  strings:
    $s1 = "var vHXg7 = new Function(\"vBs1\", '{var vRHh4 = new Date();vRHh4[\"setUTCFullYear\"](\"2003\");if (vRHh4.getUTCFullYear().toStr" ascii
    $s2 = "var vHXg7 = new Function(\"vBs1\", '{var vRHh4 = new Date();vRHh4[\"setUTCFullYear\"](\"2003\");if (vRHh4.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vKFk9 = vBs1.split(\"###\"); return vKFk9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vLQl3 = new Function(\"vBs1\", '{return vBs1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}