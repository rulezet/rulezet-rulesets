rule sig_20161207_4554d9a9d0d92b7fc43d60fae8428998 {
  meta:
    description = "datamaliciousorder - file 20161207_4554d9a9d0d92b7fc43d60fae8428998.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f2992a941e1fbff67dacab20751036012631e75d3f10713e819ab98111f4cb5"

  strings:
    $s1 = "var vRf4 = new Function(\"vUKu2\", '{var vZs6 = new Date();vZs6[\"setUTCFullYear\"](\"2003\");if (vZs6.getUTCFullYear().toString" ascii
    $s2 = "var vRf4 = new Function(\"vUKu2\", '{var vZs6 = new Date();vZs6[\"setUTCFullYear\"](\"2003\");if (vZs6.getUTCFullYear().toString" ascii
    $s3 = "var vYa8 = new Function(\"vUKu2\", '{return vUKu2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vHk4 = vUKu2.split(\"###\"); return vHk4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}