rule sig_20161207_550a1d991796574ba6f7cbbe0dfca2af {
  meta:
    description = "datamaliciousorder - file 20161207_550a1d991796574ba6f7cbbe0dfca2af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "276885af8c96434ed998b3cef39f351546dcc1f543000ef4dcc6266856b243da"

  strings:
    $s1 = "var vBu8 = new Function(\"vFBg3\", '{var vPn4 = new Date();vPn4[\"setUTCFullYear\"](\"2003\");if (vPn4.getUTCFullYear().toString" ascii
    $s2 = "var vBu8 = new Function(\"vFBg3\", '{var vPn4 = new Date();vPn4[\"setUTCFullYear\"](\"2003\");if (vPn4.getUTCFullYear().toString" ascii
    $s3 = "var vDc2 = new Function(\"vFBg3\", '{return vFBg3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vZUc7 = vFBg3.split(\"###\"); return vZUc7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}