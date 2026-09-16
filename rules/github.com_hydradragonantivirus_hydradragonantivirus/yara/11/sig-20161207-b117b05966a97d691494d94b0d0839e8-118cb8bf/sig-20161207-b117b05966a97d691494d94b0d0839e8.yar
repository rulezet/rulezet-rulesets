rule sig_20161207_b117b05966a97d691494d94b0d0839e8 {
  meta:
    description = "datamaliciousorder - file 20161207_b117b05966a97d691494d94b0d0839e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "997c8bc2d04de7d587731583b8aec598aa5be6ee204501989bea4d51f78cdf06"

  strings:
    $s1 = "var vNSd7 = new Function(\"vWBz8\", '{var vYl0 = new Date();vYl0[\"setUTCFullYear\"](\"2003\");if (vYl0.getUTCFullYear().toStrin" ascii
    $s2 = "var vNSd7 = new Function(\"vWBz8\", '{var vYl0 = new Date();vYl0[\"setUTCFullYear\"](\"2003\");if (vYl0.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vDXp9 = vWBz8.split(\"###\"); return vDXp9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vVw3 = new Function(\"vWBz8\", '{return vWBz8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}