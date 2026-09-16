rule sig_20161207_7b5122e89ff332500f3ec890ab742904 {
  meta:
    description = "datamaliciousorder - file 20161207_7b5122e89ff332500f3ec890ab742904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcf82ea63851c5e400b85ba9b4b39b4533afb5c6aa7ccc499a3a725b5bf3d8d9"

  strings:
    $s1 = "var vKGa2 = new Function(\"vKHc9\", '{var vXZm5 = new Date();vXZm5[\"setUTCFullYear\"](\"2003\");if (vXZm5.getUTCFullYear().toSt" ascii
    $s2 = "var vKGa2 = new Function(\"vKHc9\", '{var vXZm5 = new Date();vXZm5[\"setUTCFullYear\"](\"2003\");if (vXZm5.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vOb1 = vKHc9.split(\"###\"); return vOb1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vALt0 = new Function(\"vKHc9\", '{return vKHc9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}