rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aCZnhbe_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aCZnhbe_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "951d5c9a0418ed7bb68d79d32e9ab287845f80c26b1ab509c1fd1ab8d9e599b5"

  strings:
    $s1 = "S=available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}