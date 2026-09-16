rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e73538d7d80d5bd7c4b83c2308e957f4775b0caa3f43229798f9afedf583d081"

  strings:
    $s1 = "GSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}