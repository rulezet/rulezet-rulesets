import "pe"
rule _Trojan_Sysbot_Gen_Trojan_Heur_km0_sX8r3Ilid_Virus_Hijack_Gen_Tr_416 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Gen.Trojan.Heur.km0@sX8r3Ilid.vir, Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "940c6c32b4d9403adc0683ff00072c35b176846d1fce98c4e07b153de0c8b8b5"
    hash2       = "886d18937f6708af03228c320bc135ec512f33c2bd47bb7dfb17a8a8cf850bd6"
    hash3       = "fba411f3903a09da8cc0607c37229dd72298e2c3c8c1ca1750ee0f0671ee8580"
    hash4       = "6d8c603bfcd7f6687d7939efabcaf98de81a1451286bc59a8583801145393170"

  strings:
    $s1 = "Situs Porno.exe" fullword wide
    $s2 = "Situs Porno" fullword wide
    $s3 = "ADA VIRUS DI KOMPUTRYMU" fullword wide
    $s4 = "GUNAKAN AVNTIVIR YANG TERUPDATE OK " fullword wide
    $s5 = "JANGAN LUPA BACKUP DATA2 PENTING ANDA" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "11520ea06ca7a22e5ad6e376a522a4d7" and (all of them)
    ) or (all of them)
}