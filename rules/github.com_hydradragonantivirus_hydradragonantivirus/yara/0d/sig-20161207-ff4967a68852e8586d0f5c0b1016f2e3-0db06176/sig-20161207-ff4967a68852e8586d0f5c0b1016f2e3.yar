rule sig_20161207_ff4967a68852e8586d0f5c0b1016f2e3 {
  meta:
    description = "datamaliciousorder - file 20161207_ff4967a68852e8586d0f5c0b1016f2e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d33a4de201c4ae0835e15672cc737a3ea0dd04f029d7eafde2bcdf2a0b9942bf"

  strings:
    $s1 = "var vZs5 = new Function(\"vXg9\", '{var vGo0 = new Date();vGo0[\"setUTCFullYear\"](\"2003\");if (vGo0.getUTCFullYear().toString(" ascii
    $s2 = "var vZs5 = new Function(\"vXg9\", '{var vGo0 = new Date();vGo0[\"setUTCFullYear\"](\"2003\");if (vGo0.getUTCFullYear().toString(" ascii
    $s3 = "var vMJf6 = new Function(\"vXg9\", '{return vXg9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vZRe3 = vXg9.split(\"###\"); return vZRe3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}