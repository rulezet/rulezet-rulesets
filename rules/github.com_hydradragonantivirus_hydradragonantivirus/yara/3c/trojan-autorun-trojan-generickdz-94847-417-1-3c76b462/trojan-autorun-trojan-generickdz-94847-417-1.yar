rule Trojan_Autorun_Trojan_GenericKDZ_94847_417_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_417_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa3103c4931143087d58c4c4c33572e47919c053f108a745e426df5ebe1df93d"

  strings:
    $s1 = "9eProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}