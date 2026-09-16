rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_amBwvTb {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@amBwvTb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fac4ca6a0a5ee57d7ee3e5ba16b6ea66d4d32e2b5c7c07de7ff262e88758edb"

  strings:
    $s1 = "Akey ;Qc|/9Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}