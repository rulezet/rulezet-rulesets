rule TTP_XOR_WriteProcessMemory_1572 {
  strings:
    $key_1572 = { 42 00 [2] 70 22 [2] 76 17 [2] 58 17 [2] 67 0b }

  condition:
    any of them
}