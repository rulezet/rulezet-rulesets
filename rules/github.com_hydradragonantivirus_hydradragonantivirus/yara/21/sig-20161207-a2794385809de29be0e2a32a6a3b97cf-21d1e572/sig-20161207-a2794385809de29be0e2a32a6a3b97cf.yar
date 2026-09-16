rule sig_20161207_a2794385809de29be0e2a32a6a3b97cf {
  meta:
    description = "datamaliciousorder - file 20161207_a2794385809de29be0e2a32a6a3b97cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b330c871a8494883dc9aafcee50d127dcf66f2fb2b9fab5ae73e2f9f1d21f5f3"

  strings:
    $s1 = "var vSq2 = new Function(\"vJy9\", '{var vZOs5 = new Date();vZOs5[\"setUTCFullYear\"](\"2003\");if (vZOs5.getUTCFullYear().toStri" ascii
    $s2 = "var vSq2 = new Function(\"vJy9\", '{var vZOs5 = new Date();vZOs5[\"setUTCFullYear\"](\"2003\");if (vZOs5.getUTCFullYear().toStri" ascii
    $s3 = "var vAg3 = new Function(\"vJy9\", '{return vJy9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vWMm3 = vJy9.split(\"###\"); return vWMm3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}