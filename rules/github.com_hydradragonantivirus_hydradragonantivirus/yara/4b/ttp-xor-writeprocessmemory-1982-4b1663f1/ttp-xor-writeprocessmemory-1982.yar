rule TTP_XOR_WriteProcessMemory_1982 {
  strings:
    $key_1982 = { 4e f0 [2] 7c d2 [2] 7a e7 [2] 54 e7 [2] 6b fb }

  condition:
    any of them
}