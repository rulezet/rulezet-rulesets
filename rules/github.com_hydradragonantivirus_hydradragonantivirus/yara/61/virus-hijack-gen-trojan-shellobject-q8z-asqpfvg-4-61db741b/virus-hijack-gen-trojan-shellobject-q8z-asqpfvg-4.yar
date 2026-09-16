rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSQPfVg_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSQPfVg_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db48596085774254d13e1687bf8a38a442c55f36999ea90874ae03a3e8e6b93"

  strings:
    $s1 = "jOIN;,<t" fullword ascii
    $s2 = ")%IrOn" fullword ascii
    $s3 = "&{bath" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}