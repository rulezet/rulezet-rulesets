rule TTP_XOR_WriteProcessMemory_88e1 {
  strings:
    $key_88e1 = { df 93 [2] ed b1 [2] eb 84 [2] c5 84 [2] fa 98 }

  condition:
    any of them
}