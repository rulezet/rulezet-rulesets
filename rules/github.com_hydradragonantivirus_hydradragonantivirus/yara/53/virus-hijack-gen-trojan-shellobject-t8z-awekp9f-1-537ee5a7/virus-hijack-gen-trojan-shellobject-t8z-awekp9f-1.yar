rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0babf1ec980f3c3483cb7d606119019db09dcd8eabd8d94bb22271a54930b82"

  strings:
    $s1 = "!JIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}