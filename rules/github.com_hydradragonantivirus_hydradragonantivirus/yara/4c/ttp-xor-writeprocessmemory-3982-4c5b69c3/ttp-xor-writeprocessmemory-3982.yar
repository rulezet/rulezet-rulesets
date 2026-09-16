rule TTP_XOR_WriteProcessMemory_3982 {
  strings:
    $key_3982 = { 6e f0 [2] 5c d2 [2] 5a e7 [2] 74 e7 [2] 4b fb }

  condition:
    any of them
}