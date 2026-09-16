rule Trojan_Danger_Trojan_GenericKD_72597336_34_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c8d4fc905fa38af1c9f07377111f46e300e50ce112f584f8fc23b64c08557bf"

  strings:
    $s1 = "software features to upgrade or fix the software and otherwise impr" fullword ascii
    $s2 = "jUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}