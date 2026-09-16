rule sig_20161207_b993243e268a7ee1e055763283692695 {
  meta:
    description = "datamaliciousorder - file 20161207_b993243e268a7ee1e055763283692695.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57102d3dbeccf3c76c16c733b0de4b716ff41899627c15e01242376869732f1a"

  strings:
    $s1 = "var vSKf8 = new Function(\"vPq2\", '{var vUVz4 = new Date();vUVz4[\"setUTCFullYear\"](\"2003\");if (vUVz4.getUTCFullYear().toStr" ascii
    $s2 = "var vSKf8 = new Function(\"vPq2\", '{var vUVz4 = new Date();vUVz4[\"setUTCFullYear\"](\"2003\");if (vUVz4.getUTCFullYear().toStr" ascii
    $s3 = "var vZDc7 = new Function(\"vPq2\", '{return vPq2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vCLg5 = vPq2.split(\"###\"); return vCLg5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}