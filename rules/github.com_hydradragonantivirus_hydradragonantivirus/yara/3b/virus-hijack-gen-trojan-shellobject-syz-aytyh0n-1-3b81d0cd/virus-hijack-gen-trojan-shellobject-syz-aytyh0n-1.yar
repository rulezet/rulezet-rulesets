rule Virus_Hijack_Gen_Trojan_ShellObject_syZ_ayTyh0n_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.syZ@ayTyh0n_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "779011d4f8f5d8d5568b952d8fa47ec139c9e8da79d1742506f9816935fd4a1c"

  strings:
    $s1 = "Cstring too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}