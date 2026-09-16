rule sig_20161207_b43c7918d54d714890b7f404c2fd46e0 {
  meta:
    description = "datamaliciousorder - file 20161207_b43c7918d54d714890b7f404c2fd46e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b985e4e832046d3b45d4860353c3b896bb3bcd1e551352c201a08fc4394ea009"

  strings:
    $s1 = "var vHc7 = new Function(\"vSGr2\", '{var vCo3 = new Date();vCo3[\"setUTCFullYear\"](\"2003\");if (vCo3.getUTCFullYear().toString" ascii
    $s2 = "var vHc7 = new Function(\"vSGr2\", '{var vCo3 = new Date();vCo3[\"setUTCFullYear\"](\"2003\");if (vCo3.getUTCFullYear().toString" ascii
    $s3 = "var vHj0 = new Function(\"vSGr2\", '{return vSGr2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vDc2 = vSGr2.split(\"###\"); return vDc2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}