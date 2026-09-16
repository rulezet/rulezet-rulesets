rule sig_20161207_beca0735c1249dccdf43cd6d1709aa64 {
  meta:
    description = "datamaliciousorder - file 20161207_beca0735c1249dccdf43cd6d1709aa64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac8001b8483e50bce3f5dd6510e0b756da3c6c1447bb422d82bff79244c72062"

  strings:
    $s1 = "var vPSm9 = new Function(\"vKLu5\", '{var vDBj7 = new Date();vDBj7[\"setUTCFullYear\"](\"2003\");if (vDBj7.getUTCFullYear().toSt" ascii
    $s2 = "var vPSm9 = new Function(\"vKLu5\", '{var vDBj7 = new Date();vDBj7[\"setUTCFullYear\"](\"2003\");if (vDBj7.getUTCFullYear().toSt" ascii
    $s3 = "var vKZz4 = new Function(\"vKLu5\", '{return vKLu5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vJBn7 = vKLu5.split(\"###\"); return vJBn7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}