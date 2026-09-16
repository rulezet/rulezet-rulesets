rule TTP_XOR_WriteProcessMemory_4d81 {
  strings:
    $key_4d81 = { 1a f3 [2] 28 d1 [2] 2e e4 [2] 00 e4 [2] 3f f8 }

  condition:
    any of them
}