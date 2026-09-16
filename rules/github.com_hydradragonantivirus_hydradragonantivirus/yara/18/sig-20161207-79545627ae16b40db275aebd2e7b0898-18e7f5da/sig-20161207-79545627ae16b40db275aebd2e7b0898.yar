rule sig_20161207_79545627ae16b40db275aebd2e7b0898 {
  meta:
    description = "datamaliciousorder - file 20161207_79545627ae16b40db275aebd2e7b0898.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b60d0cfe5e239f1e1fd024ca406d8ea349f77bc8577baf03531be331660df9ab"

  strings:
    $s1 = "var vMWa4 = new Function(\"vWd1\", '{var vYZb7 = new Date();vYZb7[\"setUTCFullYear\"](\"2003\");if (vYZb7.getUTCFullYear().toStr" ascii
    $s2 = "var vMWa4 = new Function(\"vWd1\", '{var vYZb7 = new Date();vYZb7[\"setUTCFullYear\"](\"2003\");if (vYZb7.getUTCFullYear().toStr" ascii
    $s3 = "var vTJg3 = new Function(\"vWd1\", '{return vWd1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vNl3 = vWd1.split(\"###\"); return vNl3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}