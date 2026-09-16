rule TTP_XOR_WriteProcessMemory_4982 {
  strings:
    $key_4982 = { 1e f0 [2] 2c d2 [2] 2a e7 [2] 04 e7 [2] 3b fb }

  condition:
    any of them
}