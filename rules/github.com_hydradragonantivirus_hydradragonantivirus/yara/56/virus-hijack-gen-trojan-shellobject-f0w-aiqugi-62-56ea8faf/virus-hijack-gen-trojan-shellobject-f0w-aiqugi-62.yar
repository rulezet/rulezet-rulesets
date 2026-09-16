rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_62 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_62.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc4ec2cb68e0bbd2c6ab195fcb2de1d3eaa23e860fe94894f928a2a18180a83"

  strings:
    $s1 = "i4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}