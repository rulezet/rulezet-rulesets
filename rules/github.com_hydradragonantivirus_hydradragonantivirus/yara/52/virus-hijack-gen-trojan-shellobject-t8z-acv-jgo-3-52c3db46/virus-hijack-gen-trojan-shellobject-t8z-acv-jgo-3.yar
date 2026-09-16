rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ad11187da909795917b5b1e6c48473e5767702e961f10dfd1b583ba814b43d7"

  strings:
    $s1 = "Jvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}