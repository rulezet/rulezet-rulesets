rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8456b95f37d2223461c26e030aea7ea8aaca2ba198344cfb045172a328b377c0"

  strings:
    $s1 = "jiti $" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}