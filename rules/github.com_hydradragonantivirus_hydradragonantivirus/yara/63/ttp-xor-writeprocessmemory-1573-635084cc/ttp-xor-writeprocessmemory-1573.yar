rule TTP_XOR_WriteProcessMemory_1573 {
  strings:
    $key_1573 = { 42 01 [2] 70 23 [2] 76 16 [2] 58 16 [2] 67 0a }

  condition:
    any of them
}