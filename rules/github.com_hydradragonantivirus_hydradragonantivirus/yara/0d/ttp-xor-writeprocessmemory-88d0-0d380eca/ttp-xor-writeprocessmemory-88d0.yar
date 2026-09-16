rule TTP_XOR_WriteProcessMemory_88d0 {
  strings:
    $key_88d0 = { df a2 [2] ed 80 [2] eb b5 [2] c5 b5 [2] fa a9 }

  condition:
    any of them
}