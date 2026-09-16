rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_329_1_Virus_Sysbot_Dro_425 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_329_1.vir, Virus.Sysbot_Dropped.Generic.Malware.FPdPk!.CA7AAE98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6e7c48bdb5b3d7bd12806dbe0341abf266b8be1b9df776481594d332faca00f"
    hash2       = "ba27ab947e196bedebb9a2705d3f89d66b5dbe563d58f75c04e82ab33cc22b7a"

  strings:
    $s1 = "(The key is too long to be read.)" fullword ascii
    $s2 = "(Binary with the length of 0)" fullword ascii
    $s3 = "2(Default)" fullword ascii
    $s4 = "(Value has not been set)" fullword ascii
    $s5 = "Socket already open)Can't change value while socket is active" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}