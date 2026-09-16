rule sig_20161207_8acd8340758aeae53be8172b17a0d1bc {
  meta:
    description = "datamaliciousorder - file 20161207_8acd8340758aeae53be8172b17a0d1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13becae4b74701c9973f8b845c509aa5bbf38acd11835841f91dc464137702a6"

  strings:
    $s1 = "var vVEt6 = new Function(\"vJq0\", '{var vHNx1 = new Date();vHNx1[\"setUTCFullYear\"](\"2003\");if (vHNx1.getUTCFullYear().toStr" ascii
    $s2 = "var vVEt6 = new Function(\"vJq0\", '{var vHNx1 = new Date();vHNx1[\"setUTCFullYear\"](\"2003\");if (vHNx1.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vWb5 = vJq0.split(\"###\"); return vWb5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vOKs7 = new Function(\"vJq0\", '{return vJq0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}