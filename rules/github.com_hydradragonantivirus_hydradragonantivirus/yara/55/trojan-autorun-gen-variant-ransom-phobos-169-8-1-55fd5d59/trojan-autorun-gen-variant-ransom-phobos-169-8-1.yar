rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e405ee25aa20f306ea388a0111093bb43a0cc80dfcedd29f371c30dad2fdbe8c"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "()}, 'x_opt': None, 'f_opt': Non@" fullword ascii
    $s3 = " 'f_opt': None, 'x_seq': None, 'f_seq': None, 'attack_classes': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}