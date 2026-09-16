import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_10_1_Virus_Hija_254 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc27193790707cd9821dd7031f7ff5dea5f7daeb4af55911354bdbcb6942853"
    hash2       = "f754fefacb54d2b54d232a2465cfee59e3393fbc5a5fb1061709bebf06e74c89"

  strings:
    $s1 = "sailput cross crowd front systempathrose" fullword wide
    $s2 = "drive branchget repeat control radio trainspotnoun" fullword wide
    $s3 = "Basicfriend Hunt givepath BeBlood fairfig mouthfor" fullword wide
    $s4 = "pay c copy C " fullword ascii
    $s5 = "Size Felt Entrance Software continueadd busy" fullword wide
    $s6 = "Entrance Software" fullword wide
    $s7 = "Dividelittle Beat" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "9c372579d7314f00e433b57a0f3d2665" and (all of them)
    ) or (all of them)
}