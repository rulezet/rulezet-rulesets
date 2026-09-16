rule TTP_XOR_WriteProcessMemory_88e6 {
  strings:
    $key_88e6 = { df 94 [2] ed b6 [2] eb 83 [2] c5 83 [2] fa 9f }

  condition:
    any of them
}