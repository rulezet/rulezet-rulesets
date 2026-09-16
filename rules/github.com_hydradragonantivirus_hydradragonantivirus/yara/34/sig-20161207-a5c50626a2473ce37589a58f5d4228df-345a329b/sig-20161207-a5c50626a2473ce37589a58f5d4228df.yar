rule sig_20161207_a5c50626a2473ce37589a58f5d4228df {
  meta:
    description = "datamaliciousorder - file 20161207_a5c50626a2473ce37589a58f5d4228df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b01e0f7ffb88762cce6a18f5c7ee096a2a46c9a4947a1043147c139ed75da9"

  strings:
    $s1 = "var vIm4 = new Function(\"vRa1\", '{var vKo5 = new Date();vKo5[\"setUTCFullYear\"](\"2003\");if (vKo5.getUTCFullYear().toString(" ascii
    $s2 = "var vIm4 = new Function(\"vRa1\", '{var vKo5 = new Date();vKo5[\"setUTCFullYear\"](\"2003\");if (vKo5.getUTCFullYear().toString(" ascii
    $s3 = "var vRp2 = new Function(\"vRa1\", '{return vRa1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vLo7 = vRa1.split(\"###\"); return vLo7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}