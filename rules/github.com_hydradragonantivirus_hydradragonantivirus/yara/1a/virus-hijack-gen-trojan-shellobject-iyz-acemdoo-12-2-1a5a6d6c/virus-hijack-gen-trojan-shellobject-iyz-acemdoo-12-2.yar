rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e63602f0899799c405292cc98778920ce25fae1965b111268f8f16db985cecb"

  strings:
    $s1 = "U@stUB}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}