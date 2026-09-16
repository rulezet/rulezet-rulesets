rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd5fc9ae321d35b25b496371d34b4f27ef289e2b9ba07cc28715ed6cc77f4c51"

  strings:
    $s1 = "*hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}