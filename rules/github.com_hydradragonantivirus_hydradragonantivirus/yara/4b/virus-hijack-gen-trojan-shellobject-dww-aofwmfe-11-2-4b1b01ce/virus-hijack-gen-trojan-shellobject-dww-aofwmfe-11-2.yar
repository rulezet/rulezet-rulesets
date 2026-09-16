rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad102dae22a20a2cf3d0a718d35363b895d2d86f85998b09f0681485957e9592"

  strings:
    $s1 = "rEcCy?_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}