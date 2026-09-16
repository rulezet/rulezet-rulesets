rule sig_20161207_6cc749bceb25d4e0397686eff967dcb9 {
  meta:
    description = "datamaliciousorder - file 20161207_6cc749bceb25d4e0397686eff967dcb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2edef49c504971be27b19326194aeeb7f8044967d40f523b41a91ac1b9984018"

  strings:
    $s1 = "var vBRi2 = new Function(\"vKWm9\", '{var vLe0 = new Date();vLe0[\"setUTCFullYear\"](\"2003\");if (vLe0.getUTCFullYear().toStrin" ascii
    $s2 = "var vBRi2 = new Function(\"vKWm9\", '{var vLe0 = new Date();vLe0[\"setUTCFullYear\"](\"2003\");if (vLe0.getUTCFullYear().toStrin" ascii
    $s3 = "var vSq6 = new Function(\"vKWm9\", '{return vKWm9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vFPu8 = vKWm9.split(\"###\"); return vFPu8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}