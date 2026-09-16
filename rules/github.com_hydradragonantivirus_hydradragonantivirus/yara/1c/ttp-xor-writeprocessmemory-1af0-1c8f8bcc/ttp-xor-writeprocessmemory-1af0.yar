rule TTP_XOR_WriteProcessMemory_1af0 {
  strings:
    $key_1af0 = { 4d 82 [2] 7f a0 [2] 79 95 [2] 57 95 [2] 68 89 }

  condition:
    any of them
}