rule sig_20161207_25c7cff4286fd7df56a40b02d2c36935 {
  meta:
    description = "datamaliciousorder - file 20161207_25c7cff4286fd7df56a40b02d2c36935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3db3b0d09d864bfa4b90655ac243b89531abe36325c93b4cfb976defedbc6fa9"

  strings:
    $s1 = "var vWj8 = new Function(\"vIHa6\", '{var vTf2 = new Date();vTf2[\"setUTCFullYear\"](\"2003\");if (vTf2.getUTCFullYear().toString" ascii
    $s2 = "var vWj8 = new Function(\"vIHa6\", '{var vTf2 = new Date();vTf2[\"setUTCFullYear\"](\"2003\");if (vTf2.getUTCFullYear().toString" ascii
    $s3 = "var vAc2 = new Function(\"vIHa6\", '{return vIHa6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vXHv2 = vIHa6.split(\"###\"); return vXHv2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}