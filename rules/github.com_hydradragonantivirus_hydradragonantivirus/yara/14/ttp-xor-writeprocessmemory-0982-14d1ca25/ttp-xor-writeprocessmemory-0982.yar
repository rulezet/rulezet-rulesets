rule TTP_XOR_WriteProcessMemory_0982 {
  strings:
    $key_0982 = { 5e f0 [2] 6c d2 [2] 6a e7 [2] 44 e7 [2] 7b fb }

  condition:
    any of them
}