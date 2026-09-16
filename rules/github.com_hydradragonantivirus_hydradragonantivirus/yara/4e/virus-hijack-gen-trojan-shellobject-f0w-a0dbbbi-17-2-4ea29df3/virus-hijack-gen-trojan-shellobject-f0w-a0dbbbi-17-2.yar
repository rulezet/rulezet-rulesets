rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b44d2674a50ce9d84ef20d9d0dac3fb9fbf2c0a0c90b637e2c7fded4eb16acf7"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}