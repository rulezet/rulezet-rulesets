rule TTP_XOR_WriteProcessMemory_88b7 {
  strings:
    $key_88b7 = { df c5 [2] ed e7 [2] eb d2 [2] c5 d2 [2] fa ce }

  condition:
    any of them
}