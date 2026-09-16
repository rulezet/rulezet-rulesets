rule TTP_XOR_WriteProcessMemory_1521 {
  strings:
    $key_1521 = { 42 53 [2] 70 71 [2] 76 44 [2] 58 44 [2] 67 58 }

  condition:
    any of them
}