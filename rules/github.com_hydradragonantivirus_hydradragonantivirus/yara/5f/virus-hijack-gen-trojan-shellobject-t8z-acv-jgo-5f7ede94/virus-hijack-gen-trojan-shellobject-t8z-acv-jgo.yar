rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2856f3637b29fb95d838823df08a8f17fe1e3fa7e13f5662baed5445eb48fbc"

  strings:
    $s1 = ";virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}