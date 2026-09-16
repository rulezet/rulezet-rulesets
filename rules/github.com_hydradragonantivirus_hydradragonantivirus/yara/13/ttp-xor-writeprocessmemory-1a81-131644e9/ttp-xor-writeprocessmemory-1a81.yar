rule TTP_XOR_WriteProcessMemory_1a81 {
  strings:
    $key_1a81 = { 4d f3 [2] 7f d1 [2] 79 e4 [2] 57 e4 [2] 68 f8 }

  condition:
    any of them
}