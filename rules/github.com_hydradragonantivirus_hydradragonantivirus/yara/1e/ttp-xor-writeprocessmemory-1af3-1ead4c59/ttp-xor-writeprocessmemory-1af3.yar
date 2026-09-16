rule TTP_XOR_WriteProcessMemory_1af3 {
  strings:
    $key_1af3 = { 4d 81 [2] 7f a3 [2] 79 96 [2] 57 96 [2] 68 8a }

  condition:
    any of them
}