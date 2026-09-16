rule Virus_Hijack_Gen_Heur_Mint_Zard_30_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7beafe5842de7c5fbe79f9131b143eac1586d73c9dea8fa040a190665d6dbf93"

  strings:
    $s1 = "^OLE initialization b nbm  gh ailed.  Make sure that the OLE libraries are the correct version." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}