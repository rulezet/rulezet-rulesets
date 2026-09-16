rule sig_20161207_94ff1fd2a3e81c32bd5af4a5adb6e21a {
  meta:
    description = "datamaliciousorder - file 20161207_94ff1fd2a3e81c32bd5af4a5adb6e21a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f5cc4a3d730549108dfe710f4cbe23b7b7d668daac18a7c40b2b4be582e86a4"

  strings:
    $s1 = "var vPx6 = new Function(\"vQGq4\", '{var vCs5 = new Date();vCs5[\"setUTCFullYear\"](\"2003\");if (vCs5.getUTCFullYear().toString" ascii
    $s2 = "var vPx6 = new Function(\"vQGq4\", '{var vCs5 = new Date();vCs5[\"setUTCFullYear\"](\"2003\");if (vCs5.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vVg0 = vQGq4.split(\"###\"); return vVg0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBx3 = new Function(\"vQGq4\", '{return vQGq4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}