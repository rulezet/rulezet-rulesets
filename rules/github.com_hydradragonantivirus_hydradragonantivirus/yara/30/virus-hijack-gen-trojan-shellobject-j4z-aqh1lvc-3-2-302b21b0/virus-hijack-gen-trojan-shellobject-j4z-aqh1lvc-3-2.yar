rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d45017fa7420d68469440deb5c81a7cd8500d7b7e0828adf86e99b08ca86773b"

  strings:
    $s1 = "jEHu{OK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}