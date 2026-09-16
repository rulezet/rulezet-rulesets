rule TTP_XOR_WriteProcessMemory_88b0 {
  strings:
    $key_88b0 = { df c2 [2] ed e0 [2] eb d5 [2] c5 d5 [2] fa c9 }

  condition:
    any of them
}