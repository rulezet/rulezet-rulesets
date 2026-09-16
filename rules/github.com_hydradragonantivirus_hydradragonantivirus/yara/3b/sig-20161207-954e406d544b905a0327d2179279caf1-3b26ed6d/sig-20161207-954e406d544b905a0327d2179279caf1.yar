rule sig_20161207_954e406d544b905a0327d2179279caf1 {
  meta:
    description = "datamaliciousorder - file 20161207_954e406d544b905a0327d2179279caf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "066badea78a84dd639dff2451c293f0fc00ed0b400982709bce28f71e0b6f04b"

  strings:
    $s1 = "var vNQc3 = new Function(\"vOEl5\", '{var vMe3 = new Date();vMe3[\"setUTCFullYear\"](\"2003\");if (vMe3.getUTCFullYear().toStrin" ascii
    $s2 = "var vNQc3 = new Function(\"vOEl5\", '{var vMe3 = new Date();vMe3[\"setUTCFullYear\"](\"2003\");if (vMe3.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vHm8 = vOEl5.split(\"###\"); return vHm8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBa6 = new Function(\"vOEl5\", '{return vOEl5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}