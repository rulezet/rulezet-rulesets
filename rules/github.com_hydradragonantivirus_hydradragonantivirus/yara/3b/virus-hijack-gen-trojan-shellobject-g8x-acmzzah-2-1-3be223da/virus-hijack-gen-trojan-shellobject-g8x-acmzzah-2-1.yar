rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9990828668e65e3f0d6b159660a3cbe9cb23171d6d30291e4ebc89353cf9f29"

  strings:
    $s1 = "Frigate" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}