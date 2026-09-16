rule TTP_XOR_WriteProcessMemory_88d3 {
  strings:
    $key_88d3 = { df a1 [2] ed 83 [2] eb b6 [2] c5 b6 [2] fa aa }

  condition:
    any of them
}