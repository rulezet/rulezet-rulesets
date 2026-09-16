rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aOF3i8p_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8c375570c7eef6c787d3aa6186597786bbb0a9abd74fdb6e947f6ccaacffa38"

  strings:
    $s1 = "WR+%lazY" fullword ascii
    $s2 = "UReA}," fullword ascii
    $s3 = "JEer,a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}