rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_amCvSwc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7047fbb9f5ce0ef42e90478d40b031bc6427789483f7b266e94a9b9a44a05424"

  strings:
    $s1 = "5University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}