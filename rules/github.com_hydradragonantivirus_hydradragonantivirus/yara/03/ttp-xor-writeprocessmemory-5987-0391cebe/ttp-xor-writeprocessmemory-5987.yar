rule TTP_XOR_WriteProcessMemory_5987 {
  strings:
    $key_5987 = { 0e f5 [2] 3c d7 [2] 3a e2 [2] 14 e2 [2] 2b fe }

  condition:
    any of them
}