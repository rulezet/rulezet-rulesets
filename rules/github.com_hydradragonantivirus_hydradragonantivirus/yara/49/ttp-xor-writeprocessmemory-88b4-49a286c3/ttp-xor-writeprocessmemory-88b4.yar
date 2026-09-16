rule TTP_XOR_WriteProcessMemory_88b4 {
  strings:
    $key_88b4 = { df c6 [2] ed e4 [2] eb d1 [2] c5 d1 [2] fa cd }

  condition:
    any of them
}