rule TTP_XOR_WriteProcessMemory_1553 {
  strings:
    $key_1553 = { 42 21 [2] 70 03 [2] 76 36 [2] 58 36 [2] 67 2a }

  condition:
    any of them
}