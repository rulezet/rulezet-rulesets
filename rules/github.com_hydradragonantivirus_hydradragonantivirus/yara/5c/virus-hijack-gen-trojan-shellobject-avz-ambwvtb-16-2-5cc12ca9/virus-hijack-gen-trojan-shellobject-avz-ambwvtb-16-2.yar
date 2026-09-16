rule Virus_Hijack_Gen_Trojan_ShellObject_avZ_amBwvTb_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3121984cecddff33f8f6b01a06d18b314d50deab85cbfbc5657a0720f61f56e"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide
    $s2 = "#SPiV%V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}