rule TTP_XOR_WriteProcessMemory_1542 {
  strings:
    $key_1542 = { 42 30 [2] 70 12 [2] 76 27 [2] 58 27 [2] 67 3b }

  condition:
    any of them
}