rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b1110f068f88a34586c553674493ddcf18312d6a4290bb16522b81b55a32603"

  strings:
    $s1 = "@[assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}