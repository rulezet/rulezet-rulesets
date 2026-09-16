rule sig_20161207_cff76e14aa5336f9a2be86ca5393e938 {
  meta:
    description = "datamaliciousorder - file 20161207_cff76e14aa5336f9a2be86ca5393e938.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45543eb3f4c3fc288da04da13ba147b64667365a5ae015d304b25faf44b6cdff"

  strings:
    $s1 = "var vOVy2 = new Function(\"vWJn0\", '{var vFZj0 = new Date();vFZj0[\"setUTCFullYear\"](\"2003\");if (vFZj0.getUTCFullYear().toSt" ascii
    $s2 = "var vOVy2 = new Function(\"vWJn0\", '{var vFZj0 = new Date();vFZj0[\"setUTCFullYear\"](\"2003\");if (vFZj0.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vAu6 = vWJn0.split(\"###\"); return vAu6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vVj4 = new Function(\"vWJn0\", '{return vWJn0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}