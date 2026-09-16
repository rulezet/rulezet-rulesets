rule Trojan_Autorun_Gen_Trojan_Chinky_2_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Chinky.2_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c9c43a224ed5bd802f0f050d98a36c0a10b32dd8ad14d43ae96478cc93454e9"

  strings:
    $s1 = ";hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}