rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae9278f424030deceed5bbc6b1d442c55388dc0d875ba1ff05e8492cf67d49bb"

  strings:
    $s1 = "PoRr)Z9" fullword ascii
    $s2 = "S&ReaK" fullword ascii
    $s3 = "{Samen" fullword ascii
    $s4 = "uruS]?" fullword ascii
    $s5 = "(@feeD" fullword ascii
    $s6 = "}Urari" fullword ascii
    $s7 = "+*Cede" fullword ascii
    $s8 = "(@feiF" fullword ascii
    $s9 = ">GelL." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}