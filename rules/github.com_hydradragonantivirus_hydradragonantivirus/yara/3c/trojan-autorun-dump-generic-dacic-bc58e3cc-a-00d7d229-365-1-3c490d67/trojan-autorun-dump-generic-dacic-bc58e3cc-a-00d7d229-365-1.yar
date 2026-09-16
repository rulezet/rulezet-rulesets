rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_365_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc9919e0fd7a8ea3a7a7925c9a16e9bdb396f1ec4c16a545698e16512a8b4868"

  strings:
    $s1 = "enumerate(DataLoader)#_SingleProcessDataLoaderIter.__next__" fullword ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = "ne, 'optimizer_scheduler': None," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}