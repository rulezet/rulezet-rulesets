rule TTP_XOR_WriteProcessMemory_8ee7 {
  strings:
    $key_8ee7 = { d9 95 [2] eb b7 [2] ed 82 [2] c3 82 [2] fc 9e }

  condition:
    any of them
}