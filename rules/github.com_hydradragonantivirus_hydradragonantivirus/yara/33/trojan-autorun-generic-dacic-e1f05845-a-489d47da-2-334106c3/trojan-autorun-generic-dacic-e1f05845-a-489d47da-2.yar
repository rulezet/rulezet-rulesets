rule Trojan_Autorun_Generic_Dacic_E1F05845_A_489D47DA_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.E1F05845.A.489D47DA_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f15b265fd107f53f426e4b55e51aa13ee09fa817e9e43e1bb143633c194f017b"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "()}, 'x_opt': None, 'f_opt': Non@" fullword ascii
    $s3 = " 'f_opt': None, 'x_seq': None, 'f_seq': None, 'attack_classes': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}