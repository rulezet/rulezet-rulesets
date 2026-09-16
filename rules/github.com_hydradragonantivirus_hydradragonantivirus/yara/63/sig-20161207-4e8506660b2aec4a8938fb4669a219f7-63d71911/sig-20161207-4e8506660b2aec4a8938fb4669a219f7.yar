rule sig_20161207_4e8506660b2aec4a8938fb4669a219f7 {
  meta:
    description = "datamaliciousorder - file 20161207_4e8506660b2aec4a8938fb4669a219f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74e922e0bfde8d8ae2d019071aaccc16709a5d3aaf3b2e168e05cebc6fcdb895"

  strings:
    $s1 = "var vQDc7 = new Function(\"vXy6\", '{var vOu0 = new Date();vOu0[\"setUTCFullYear\"](\"2003\");if (vOu0.getUTCFullYear().toString" ascii
    $s2 = "var vQDc7 = new Function(\"vXy6\", '{var vOu0 = new Date();vOu0[\"setUTCFullYear\"](\"2003\");if (vOu0.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vBb0 = vXy6.split(\"###\"); return vBb0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWEy9 = new Function(\"vXy6\", '{return vXy6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}