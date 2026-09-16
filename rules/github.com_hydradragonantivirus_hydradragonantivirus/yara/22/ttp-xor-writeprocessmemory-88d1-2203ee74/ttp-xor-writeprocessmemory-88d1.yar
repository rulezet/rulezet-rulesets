rule TTP_XOR_WriteProcessMemory_88d1 {
  strings:
    $key_88d1 = { df a3 [2] ed 81 [2] eb b4 [2] c5 b4 [2] fa a8 }

  condition:
    any of them
}