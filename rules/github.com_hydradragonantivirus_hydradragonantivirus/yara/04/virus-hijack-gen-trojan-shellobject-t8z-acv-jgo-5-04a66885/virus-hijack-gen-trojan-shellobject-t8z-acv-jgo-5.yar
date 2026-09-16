rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75283f11f457b3484279cacbbb257ec0c0de06421c4c8ba70cf993e50886cf32"

  strings:
    $s1 = "c}virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}