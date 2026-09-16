import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_39_2_Virus_Hijac_383 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_39_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fea9d7223b4ac87084a773d54ff13204f1a7faa64d81b3c60075326b73a1a20e"
    hash2       = "b17c2814ba9f76e7b2731436cd503764b5850f649c1e6c652fcd999fe41899d2"

  strings:
    $s1 = "starriness" fullword wide
    $s2 = "Bleachman" fullword wide
    $s3 = "Resizable Window" fullword ascii
    $s4 = "Dabber" fullword ascii
    $s5 = "You can insert code here for loading a help file." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "99a584995218ab6c1a30f8523361bbbf" and (all of them)
    ) or (all of them)
}