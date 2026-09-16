rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad6226432b44f8420757e0c5ac42b4bbad87f832e9806cabb47123446ed6919a"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}