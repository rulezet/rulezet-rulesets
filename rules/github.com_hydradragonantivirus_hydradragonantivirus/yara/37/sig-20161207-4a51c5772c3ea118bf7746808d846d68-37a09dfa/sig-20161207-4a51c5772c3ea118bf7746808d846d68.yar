rule sig_20161207_4a51c5772c3ea118bf7746808d846d68 {
  meta:
    description = "datamaliciousorder - file 20161207_4a51c5772c3ea118bf7746808d846d68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af33f0641fc57d8dbd42d1806a7668af053d64d9b06ee30db22de2f1aa4c5378"

  strings:
    $s1 = "var vKYm9 = new Function(\"vXBp0\", '{var vZHf4 = new Date();vZHf4[\"setUTCFullYear\"](\"2003\");if (vZHf4.getUTCFullYear().toSt" ascii
    $s2 = "var vKYm9 = new Function(\"vXBp0\", '{var vZHf4 = new Date();vZHf4[\"setUTCFullYear\"](\"2003\");if (vZHf4.getUTCFullYear().toSt" ascii
    $s3 = "var vAXe1 = new Function(\"vXBp0\", '{return vXBp0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vXCj5 = vXBp0.split(\"###\"); return vXCj5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}