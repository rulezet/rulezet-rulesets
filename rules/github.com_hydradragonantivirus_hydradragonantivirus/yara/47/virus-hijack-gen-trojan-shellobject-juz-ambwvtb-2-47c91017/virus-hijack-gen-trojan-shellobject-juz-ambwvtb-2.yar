rule Virus_Hijack_Gen_Trojan_ShellObject_juZ_amBwvTb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.juZ@amBwvTb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59fd02b506a427a1d7eed04c99f29972b7675adae33d9daa1b857f7a00c658cb"

  strings:
    $s1 = "$maSK##" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}