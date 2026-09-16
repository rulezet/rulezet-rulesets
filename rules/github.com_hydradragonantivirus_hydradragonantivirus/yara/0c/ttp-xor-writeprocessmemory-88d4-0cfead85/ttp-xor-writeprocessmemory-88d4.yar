rule TTP_XOR_WriteProcessMemory_88d4 {
  strings:
    $key_88d4 = { df a6 [2] ed 84 [2] eb b1 [2] c5 b1 [2] fa ad }

  condition:
    any of them
}