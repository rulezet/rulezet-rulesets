rule sig_20161207_b4f0b59fec478de32cce5c2262e83469 {
  meta:
    description = "datamaliciousorder - file 20161207_b4f0b59fec478de32cce5c2262e83469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95d7664cb50681825af3784c079374f3b741de68b50a631b27ba20bcd4fa2da1"

  strings:
    $s1 = "var vVe8 = new Function(\"vCOp5\", '{var vOVa6 = new Date();vOVa6[\"setUTCFullYear\"](\"2003\");if (vOVa6.getUTCFullYear().toStr" ascii
    $s2 = "var vVe8 = new Function(\"vCOp5\", '{var vOVa6 = new Date();vOVa6[\"setUTCFullYear\"](\"2003\");if (vOVa6.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vQXa7 = vCOp5.split(\"###\"); return vQXa7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSb6 = new Function(\"vCOp5\", '{return vCOp5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}