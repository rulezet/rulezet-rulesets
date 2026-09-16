rule Trojan_Autorun_Gen_Trojan_Backdoor2_FmJfaGT28okb_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.FmJfaGT28okb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6753523d4349a79feeba1f838e82162db171990b8e52a4da537efaf7b340cb8"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "()}, 'x_opt': None, 'f_opt': Non@" fullword ascii
    $s3 = " 'f_opt': None, 'x_seq': None, 'f_seq': None, 'attack_classes': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}