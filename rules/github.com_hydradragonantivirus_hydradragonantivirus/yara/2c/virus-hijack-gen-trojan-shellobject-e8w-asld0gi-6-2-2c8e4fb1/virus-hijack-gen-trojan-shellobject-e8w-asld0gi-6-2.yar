rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc122026ff887be142999d6d85fd363b461c912bd27f96221a7123d4629ceec"

  strings:
    $s1 = "Fise nogifakeku honi vaso. Woma za jitezapuva. Yitolohu re jevutusibebi. Cixidusawerice cizaxafixobamo yeveti zababa. Gewoxodoce" ascii
    $s2 = "Fise nogifakeku honi vaso. Woma za jitezapuva. Yitolohu re jevutusibebi. Cixidusawerice cizaxafixobamo yeveti zababa. Gewoxodoce" ascii
    $s3 = "Tagarozuka foto vibi bozu. Ve. Mayu zutedoraju xejilizuyowi jufebodoyilu bulicokibagegu. Zovewana veto gisadayar. " fullword ascii
    $s4 = "m cannot be run in DOS mode." fullword ascii
    $s5 = "!This " fullword ascii
    $s6 = "sapa jayeyazedexi sudo yomuhosadegumo fipasicajocowe. Nodipececi. Dujuci yexawe koza rixecu. Fazukofa. Tepaxudoca. Gigiyove keso" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}