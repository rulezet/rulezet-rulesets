rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cee3e5e0a65782f1b52d26d56866847c8c2204a82092cecaeb4bb8eaf59a3b1"

  strings:
    $s1 = "@P%CRab" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}