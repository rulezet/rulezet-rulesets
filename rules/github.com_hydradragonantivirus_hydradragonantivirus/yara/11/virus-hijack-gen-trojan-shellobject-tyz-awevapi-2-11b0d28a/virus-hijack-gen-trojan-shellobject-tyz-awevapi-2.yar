rule Virus_Hijack_Gen_Trojan_ShellObject_tyZ_aWevApi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aWevApi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2304789c0b807050120db93da2c57178bac0707a20a55adf7cd2384b96cab15"

  strings:
    $s1 = "Internal Compiler Bug: No runtime type matcher." fullword ascii
    $s2 = "Windows Sound Recorder" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}