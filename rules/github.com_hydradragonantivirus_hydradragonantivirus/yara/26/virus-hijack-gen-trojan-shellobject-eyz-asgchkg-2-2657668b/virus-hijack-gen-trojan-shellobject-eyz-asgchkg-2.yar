rule Virus_Hijack_Gen_Trojan_ShellObject_EyZ_aSgChKg_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EyZ@aSgChKg_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c764ef9ce28e94ccc15d7ff9c84ad4053063eff926d0197bc7b9dfb61070942"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, @^U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}