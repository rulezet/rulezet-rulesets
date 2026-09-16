rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aSZtDuk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aSZtDuk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ac24d94b5b8192db8a616c3e498c829b1bb3433a6c44269fb4436cb5b60895a"

  strings:
    $s1 = "gor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}