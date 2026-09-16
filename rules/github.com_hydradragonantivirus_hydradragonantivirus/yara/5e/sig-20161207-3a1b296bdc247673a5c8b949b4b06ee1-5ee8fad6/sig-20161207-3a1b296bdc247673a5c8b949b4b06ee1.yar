rule sig_20161207_3a1b296bdc247673a5c8b949b4b06ee1 {
  meta:
    description = "datamaliciousorder - file 20161207_3a1b296bdc247673a5c8b949b4b06ee1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fca4ce62ad4164bdc1e2ecca5b66820f5436745b6e092e1b9cb98a9dccc5c16"

  strings:
    $s1 = "var vKWo3 = new Function(\"vYNw8\", '{var vPLj2 = new Date();vPLj2[\"setUTCFullYear\"](\"2003\");if (vPLj2.getUTCFullYear().toSt" ascii
    $s2 = "var vKWo3 = new Function(\"vYNw8\", '{var vPLj2 = new Date();vPLj2[\"setUTCFullYear\"](\"2003\");if (vPLj2.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vFYy6 = vYNw8.split(\"###\"); return vFYy6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWLt5 = new Function(\"vYNw8\", '{return vYNw8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}