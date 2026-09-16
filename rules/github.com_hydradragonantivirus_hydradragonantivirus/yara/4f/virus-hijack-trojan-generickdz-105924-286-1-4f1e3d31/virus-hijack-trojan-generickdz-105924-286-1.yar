rule Virus_Hijack_Trojan_GenericKDZ_105924_286_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_286_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "642c7d6d44dae2894f15a4e050b661e75498e0f1d7fa52471d57f0bbaa031615"

  strings:
    $s1 = "nSyfycFQ4OqL2WM61m.rLXmQOot9HCQyQsyfy+NTCaUWUH7uLtRnWs1d+Ty1i44Wk0TAmp688Yi`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
    $s2 = "<Module>{4D12D636-034A-4A68-8DF8-B73235C3C277}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}