rule VirusShareTrojanSiggen1527075 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1527075.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "448967b377216a712b478014c50cd629c0206d2dd92ab9c0dae06a7664a5319e"

  strings:
    $s1 = "start .gmx82.sfx.exe -pflappy" fullword ascii
    $s2 = "@%weLT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}