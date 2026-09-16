rule sig_20161207_1637705ab255cb3bdaf8121299dba647 {
  meta:
    description = "datamaliciousorder - file 20161207_1637705ab255cb3bdaf8121299dba647.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25a7e21d641c14263f3a2e48fda5af391c885c81c4754f03fb23c66f5ffd0d95"

  strings:
    $s1 = "var vYt5 = new Function(\"vFl4\", '{var vPFb8 = new Date();vPFb8[\"setUTCFullYear\"](\"2003\");if (vPFb8.getUTCFullYear().toStri" ascii
    $s2 = "var vYt5 = new Function(\"vFl4\", '{var vPFb8 = new Date();vPFb8[\"setUTCFullYear\"](\"2003\");if (vPFb8.getUTCFullYear().toStri" ascii
    $s3 = "var vVy9 = new Function(\"vFl4\", '{return vFl4.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vZa5 = vFl4.split(\"###\"); return vZa5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}