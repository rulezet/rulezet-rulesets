rule TTP_XOR_WriteProcessMemory_8e84 {
  strings:
    $key_8e84 = { d9 f6 [2] eb d4 [2] ed e1 [2] c3 e1 [2] fc fd }

  condition:
    any of them
}