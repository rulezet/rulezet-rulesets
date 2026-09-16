rule sig_20161207_5519db944d8615d01b4a52438fe8e94a {
  meta:
    description = "datamaliciousorder - file 20161207_5519db944d8615d01b4a52438fe8e94a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "105531626a97a54139a41e58e03842fd37ae52ba80ca4c66aea03b4debd186fd"

  strings:
    $s1 = "var vRg6 = new Function(\"vPXf2\", '{var vNSu5 = new Date();vNSu5[\"setUTCFullYear\"](\"2003\");if (vNSu5.getUTCFullYear().toStr" ascii
    $s2 = "var vRg6 = new Function(\"vPXf2\", '{var vNSu5 = new Date();vNSu5[\"setUTCFullYear\"](\"2003\");if (vNSu5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vCh0 = vPXf2.split(\"###\"); return vCh0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vIYf9 = new Function(\"vPXf2\", '{return vPXf2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}