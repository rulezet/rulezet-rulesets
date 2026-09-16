rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da2a5aef6a785f975a64d74aa28d003d67f564f40265b59bf1f15954f8ac66d1"

  strings:
    $s1 = "{that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}