rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_aeWgNZc_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@aeWgNZc_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988b6655ff81f2146b17ffc791516f5dceef44b5cedfac08c0922c8d5acdbfe7"

  strings:
    $s1 = "[+]Got the address to write 0x%x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}