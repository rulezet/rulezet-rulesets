rule sig_20161207_c0153d689c496e4999f2793182015809 {
  meta:
    description = "datamaliciousorder - file 20161207_c0153d689c496e4999f2793182015809.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eff3b3c90f365127cb339f2c5c18372edfb4d85b13d38f2185cb8c3d0bcd9642"

  strings:
    $s1 = "var vYEz0 = new Function(\"vPs6\", '{var vQDj2 = new Date();vQDj2[\"setUTCFullYear\"](\"2003\");if (vQDj2.getUTCFullYear().toStr" ascii
    $s2 = "var vYEz0 = new Function(\"vPs6\", '{var vQDj2 = new Date();vQDj2[\"setUTCFullYear\"](\"2003\");if (vQDj2.getUTCFullYear().toStr" ascii
    $s3 = "var vJWz4 = new Function(\"vPs6\", '{return vPs6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vQQl8 = vPs6.split(\"###\"); return vQQl8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}