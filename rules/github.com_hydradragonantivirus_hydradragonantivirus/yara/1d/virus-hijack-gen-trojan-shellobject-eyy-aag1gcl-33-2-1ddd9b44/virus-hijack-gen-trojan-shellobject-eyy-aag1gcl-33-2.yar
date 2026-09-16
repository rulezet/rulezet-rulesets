rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_33_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_33_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6193da9928a776ec36d0d80a457dd81661d5c7eae03348712205b7a4ab08b5a4"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}