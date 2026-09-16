rule TTP_XOR_WriteProcessMemory_7982 {
  strings:
    $key_7982 = { 2e f0 [2] 1c d2 [2] 1a e7 [2] 34 e7 [2] 0b fb }

  condition:
    any of them
}