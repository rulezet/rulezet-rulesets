rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_au0WBJh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@au0WBJh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97de48ea2e5f638897cc6af9889bc141262e48b1bddbc8fca532e46e5e9e388a"

  strings:
    $s1 = ">Horders during any 12 month period." fullword ascii
    $s2 = "CHAwk>ZkJ{" fullword ascii
    $s3 = "CHAwk>ZkfA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}