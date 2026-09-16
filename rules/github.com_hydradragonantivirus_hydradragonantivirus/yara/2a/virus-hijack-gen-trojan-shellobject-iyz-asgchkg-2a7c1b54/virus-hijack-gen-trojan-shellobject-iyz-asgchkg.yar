rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aSgChKg {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aSgChKg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cf4cbaef7c303ad47281c1fb86472fbc917291ee48d5c70e84a850a8ef26624"

  strings:
    $s1 = ">rEnd)M%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}