rule sig_20161207_28fc4383d2578c00e7bcff0c5c1da87f {
  meta:
    description = "datamaliciousorder - file 20161207_28fc4383d2578c00e7bcff0c5c1da87f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f469b631d24c95aa9101cce3316ca78f16359555559ef5495bb044af383e73"

  strings:
    $s1 = "var vSc6 = new Function(\"vJg5\", '{var vRd9 = new Date();vRd9[\"setUTCFullYear\"](\"2003\");if (vRd9.getUTCFullYear().toString(" ascii
    $s2 = "var vSc6 = new Function(\"vJg5\", '{var vRd9 = new Date();vRd9[\"setUTCFullYear\"](\"2003\");if (vRd9.getUTCFullYear().toString(" ascii
    $s3 = "var vFv9 = new Function(\"vJg5\", '{return vJg5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vXPs4 = vJg5.split(\"###\"); return vXPs4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}