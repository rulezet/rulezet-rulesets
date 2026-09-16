rule sig_20161207_06d6b6900dcb36bad1b04373e9d96495 {
  meta:
    description = "datamaliciousorder - file 20161207_06d6b6900dcb36bad1b04373e9d96495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3da1b88032fcab004b4bbcdf6d9488252f8ad7070f5f743b064a76f0d0cd23fd"

  strings:
    $s1 = "var vFi1 = new Function(\"vEc9\", '{var vQEf4 = new Date();vQEf4[\"setUTCFullYear\"](\"2003\");if (vQEf4.getUTCFullYear().toStri" ascii
    $s2 = "var vFi1 = new Function(\"vEc9\", '{var vQEf4 = new Date();vQEf4[\"setUTCFullYear\"](\"2003\");if (vQEf4.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vSs5 = vEc9.split(\"###\"); return vSs5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWq9 = new Function(\"vEc9\", '{return vEc9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}