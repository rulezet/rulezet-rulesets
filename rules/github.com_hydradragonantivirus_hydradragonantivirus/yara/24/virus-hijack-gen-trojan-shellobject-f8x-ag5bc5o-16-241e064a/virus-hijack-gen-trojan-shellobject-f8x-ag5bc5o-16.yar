rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1177d9685fcfa92b1f3ccbd97057633bcc37c6696c12144f325fd87787f0c546"

  strings:
    $s1 = "Ohundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}