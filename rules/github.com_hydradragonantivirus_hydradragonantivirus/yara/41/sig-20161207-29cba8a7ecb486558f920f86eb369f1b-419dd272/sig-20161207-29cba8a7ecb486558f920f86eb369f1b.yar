rule sig_20161207_29cba8a7ecb486558f920f86eb369f1b {
  meta:
    description = "datamaliciousorder - file 20161207_29cba8a7ecb486558f920f86eb369f1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c08794733e177e1085b95e6071772b529e0ebe1132bbdc9b8341d67c785aa1"

  strings:
    $s1 = "var vRFm4 = new Function(\"vBk9\", '{var vGEi5 = new Date();vGEi5[\"setUTCFullYear\"](\"2003\");if (vGEi5.getUTCFullYear().toStr" ascii
    $s2 = "var vRFm4 = new Function(\"vBk9\", '{var vGEi5 = new Date();vGEi5[\"setUTCFullYear\"](\"2003\");if (vGEi5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vSOm2 = vBk9.split(\"###\"); return vSOm2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vXCd5 = new Function(\"vBk9\", '{return vBk9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}