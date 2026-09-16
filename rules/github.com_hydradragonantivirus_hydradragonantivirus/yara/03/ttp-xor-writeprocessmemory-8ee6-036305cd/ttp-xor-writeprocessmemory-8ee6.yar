rule TTP_XOR_WriteProcessMemory_8ee6 {
  strings:
    $key_8ee6 = { d9 94 [2] eb b6 [2] ed 83 [2] c3 83 [2] fc 9f }

  condition:
    any of them
}