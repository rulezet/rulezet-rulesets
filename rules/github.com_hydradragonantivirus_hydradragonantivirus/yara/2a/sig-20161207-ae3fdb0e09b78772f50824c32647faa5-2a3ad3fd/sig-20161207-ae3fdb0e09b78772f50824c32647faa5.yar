rule sig_20161207_ae3fdb0e09b78772f50824c32647faa5 {
  meta:
    description = "datamaliciousorder - file 20161207_ae3fdb0e09b78772f50824c32647faa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dff2dfa6c1dbc2fabce389a739b32118a50071c4dff7108603fdb38dfcf78f8"

  strings:
    $s1 = "var vEf5 = new Function(\"vJEv4\", '{var vHp2 = new Date();vHp2[\"setUTCFullYear\"](\"2003\");if (vHp2.getUTCFullYear().toString" ascii
    $s2 = "var vEf5 = new Function(\"vJEv4\", '{var vHp2 = new Date();vHp2[\"setUTCFullYear\"](\"2003\");if (vHp2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vREb6 = vJEv4.split(\"###\"); return vREb6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSm3 = new Function(\"vJEv4\", '{return vJEv4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}