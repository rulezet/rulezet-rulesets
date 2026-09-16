rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_282 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_282.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa64275b27a32eb554d2fd0170e9490e700d846ffb8278ced3de277c735911bc"

  strings:
    $s1 = "enumerate(DataLoader)#_SingleProcessDataLoaderIter.__next__" fullword ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = "ne, 'optimizer_scheduler': None," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}