rule TTP_XOR_WriteProcessMemory_1556 {
  strings:
    $key_1556 = { 42 24 [2] 70 06 [2] 76 33 [2] 58 33 [2] 67 2f }

  condition:
    any of them
}