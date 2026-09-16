rule Trojan_Danger_Trojan_GenericKD_72304918_213 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_213.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2931018d3f2176ab705ea9bb68f41bf4f8c35613033f58fa8b0421cf678bbf7"

  strings:
    $s1 = "ODBC Data Sources (32-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}