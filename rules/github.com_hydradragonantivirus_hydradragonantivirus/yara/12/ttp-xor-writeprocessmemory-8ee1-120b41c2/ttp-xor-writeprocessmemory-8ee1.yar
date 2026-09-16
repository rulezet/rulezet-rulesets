rule TTP_XOR_WriteProcessMemory_8ee1 {
  strings:
    $key_8ee1 = { d9 93 [2] eb b1 [2] ed 84 [2] c3 84 [2] fc 98 }

  condition:
    any of them
}