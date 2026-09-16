rule sig_20161207_95c71ba233c2ebd5c681dfc5a3c37c21 {
  meta:
    description = "datamaliciousorder - file 20161207_95c71ba233c2ebd5c681dfc5a3c37c21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86cec0de1f0e3392137b461bf19380e1eb3e9bdd0c9a5a281572c6830b75f012"

  strings:
    $s1 = "var vMTz4 = new Function(\"vRMn8\", '{var vMZf9 = new Date();vMZf9[\"setUTCFullYear\"](\"2003\");if (vMZf9.getUTCFullYear().toSt" ascii
    $s2 = "var vMTz4 = new Function(\"vRMn8\", '{var vMZf9 = new Date();vMZf9[\"setUTCFullYear\"](\"2003\");if (vMZf9.getUTCFullYear().toSt" ascii
    $s3 = "var vVEm3 = new Function(\"vRMn8\", '{return vRMn8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vHWl1 = vRMn8.split(\"###\"); return vHWl1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}