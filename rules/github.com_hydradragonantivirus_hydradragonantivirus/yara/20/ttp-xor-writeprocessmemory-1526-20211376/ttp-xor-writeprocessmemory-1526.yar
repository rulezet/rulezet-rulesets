rule TTP_XOR_WriteProcessMemory_1526 {
  strings:
    $key_1526 = { 42 54 [2] 70 76 [2] 76 43 [2] 58 43 [2] 67 5f }

  condition:
    any of them
}