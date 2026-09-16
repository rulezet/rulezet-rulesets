rule sig_20161207_3daaecf996689656f1bbc36c50bfeb1c {
  meta:
    description = "datamaliciousorder - file 20161207_3daaecf996689656f1bbc36c50bfeb1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a02d916bafaa9f1af999cecbf7ba75f87789919a1a110a8e01414c216b534ae0"

  strings:
    $s1 = "var vNd1 = new Function(\"vLg0\", '{var vIKl7 = new Date();vIKl7[\"setUTCFullYear\"](\"2003\");if (vIKl7.getUTCFullYear().toStri" ascii
    $s2 = "var vNd1 = new Function(\"vLg0\", '{var vIKl7 = new Date();vIKl7[\"setUTCFullYear\"](\"2003\");if (vIKl7.getUTCFullYear().toStri" ascii
    $s3 = "var vOs8 = new Function(\"vLg0\", '{return vLg0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vLRk9 = vLg0.split(\"###\"); return vLRk9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}