rule TTP_XOR_WriteProcessMemory_1551 {
  strings:
    $key_1551 = { 42 23 [2] 70 01 [2] 76 34 [2] 58 34 [2] 67 28 }

  condition:
    any of them
}