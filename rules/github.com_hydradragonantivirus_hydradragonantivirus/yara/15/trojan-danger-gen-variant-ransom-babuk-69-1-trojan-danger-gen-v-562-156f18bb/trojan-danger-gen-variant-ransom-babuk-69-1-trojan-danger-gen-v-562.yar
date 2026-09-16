import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Babuk_69_1_Trojan_Danger_Gen_V_562 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Babuk.69_1.vir, Trojan.Danger_Gen.Variant.Ransom.Babuk.69_2.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_715_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_718_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_725_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_727_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_729_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_72_1.vir, Virus.Hijack_Gen.Variant.Ransom.Babuk.69.vir, Virus.Hijack_Gen.Variant.Ransom.Babuk.69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a778df918ff246de63ea910513755289f85ec22fc18fe7ec6fb6b6f4f184657"
    hash2       = "a4d21e51ee33832827e7a6150b3f80c266386651152214ff31aa8db3f070edaa"
    hash3       = "38241905ab597c27a1a29cbbae1e908c37b2c445a564107d9e6c53bf197eb949"
    hash4       = "6e85c4fd1e54fcd5c8f743ed60b760a41ff3a468470bcafd07678089bfd8329a"
    hash5       = "deeca5d634b19e0c55198f3cc6d34e031b3eb53205320ccff64e854b60f8cca4"
    hash6       = "5cc61cfc4ed9ada680ed919a7b90485e2d0e9093deaa965c98e3c18c1cc662d5"
    hash7       = "5c483b03cda15695b62f5b7d7c58d978c41e66f3f9e043bc66b756b24bbae2a4"
    hash8       = "9b10b484de5bb4db8a6d57bbfd68b290447cb1aa8d726df742af39440f11edf5"
    hash9       = "00d9916e795c53f32af24edd5b808b6dc3d51ff364b032027cb62b4e2b7802bf"
    hash10      = "9cfe05c0304b6e3ec6f8f3428be4305041ba7270f3f17d24c68a031cb8f70a21"

  strings:
    $s1 = "multiple servers, regardless of whether the individual is actively using the programs at any given time. A non human operatD" fullword ascii
    $s2 = " the user of a licensed copy of the software, or a product that includes the software, with activeProfessional User " fullword ascii
    $s3 = "efinition of \"full-time\" and \"part-time\" is based on" fullword ascii
    $s4 = "m not allowed to do with the software? Yes. Because the software is licensed, institution counts as 25% of an FTE Student. The d" ascii
    $s5 = "m not allowed to do with the software? Yes. Because the software is licensed, institution counts as 25% of an FTE Student. The d" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c9f0cc749492c31c159a3ba965b3ae90" and (all of them)
    ) or (all of them)
}