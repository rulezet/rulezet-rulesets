rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_amCvSwc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@amCvSwc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96b078496b4e7236a8492d91157847c5526c8bf1660ca9ca0841ec22744713a7"

  strings:
    $s1 = "3University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}