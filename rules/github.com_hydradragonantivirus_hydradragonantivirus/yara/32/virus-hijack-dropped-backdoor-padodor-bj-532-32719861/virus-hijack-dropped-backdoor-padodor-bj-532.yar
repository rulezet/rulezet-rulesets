rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_532 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_532.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0a79d122f1bd17ca538a15b14c3143e19a238f4039129d719fb837467c8d51"

  strings:
    $s1 = "enumerate(DataLoader)#_SingleProcessDataLoaderIter.__next__" fullword ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = "ne, 'optimizer_scheduler': None," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}