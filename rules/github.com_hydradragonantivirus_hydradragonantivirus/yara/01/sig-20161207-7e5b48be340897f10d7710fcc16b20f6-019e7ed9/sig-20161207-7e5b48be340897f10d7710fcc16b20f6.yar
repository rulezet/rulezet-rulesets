rule sig_20161207_7e5b48be340897f10d7710fcc16b20f6 {
  meta:
    description = "datamaliciousorder - file 20161207_7e5b48be340897f10d7710fcc16b20f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28caeb44519a4866c28c8d9d97997be0e90cb39ef4b5c3aed544ba35e0510a3b"

  strings:
    $s1 = "var vRKd7 = new Function(\"vCZc1\", '{var vPl4 = new Date();vPl4[\"setUTCFullYear\"](\"2003\");if (vPl4.getUTCFullYear().toStrin" ascii
    $s2 = "var vRKd7 = new Function(\"vCZc1\", '{var vPl4 = new Date();vPl4[\"setUTCFullYear\"](\"2003\");if (vPl4.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vNSp3 = vCZc1.split(\"###\"); return vNSp3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vPKo7 = new Function(\"vCZc1\", '{return vCZc1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}