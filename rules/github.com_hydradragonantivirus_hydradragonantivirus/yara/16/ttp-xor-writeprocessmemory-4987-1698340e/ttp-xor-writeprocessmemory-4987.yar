rule TTP_XOR_WriteProcessMemory_4987 {
  strings:
    $key_4987 = { 1e f5 [2] 2c d7 [2] 2a e2 [2] 04 e2 [2] 3b fe }

  condition:
    any of them
}