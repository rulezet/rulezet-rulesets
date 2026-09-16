rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_269_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_269_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96c5dc5222eedbcb19470bc0f0ce2d7590bd11ca6cacd358eba3a796176a25f5"

  strings:
    $s1 = "enumerate(DataLoader)#_SingleProcessDataLoaderIter.__next__" fullword ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = "ne, 'optimizer_scheduler': None," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}