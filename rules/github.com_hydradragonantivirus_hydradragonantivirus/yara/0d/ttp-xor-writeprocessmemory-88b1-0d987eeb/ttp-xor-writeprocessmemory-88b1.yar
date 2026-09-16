rule TTP_XOR_WriteProcessMemory_88b1 {
  strings:
    $key_88b1 = { df c3 [2] ed e1 [2] eb d4 [2] c5 d4 [2] fa c8 }

  condition:
    any of them
}