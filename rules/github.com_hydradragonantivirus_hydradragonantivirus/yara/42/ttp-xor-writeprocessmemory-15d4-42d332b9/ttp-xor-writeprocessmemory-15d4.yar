rule TTP_XOR_WriteProcessMemory_15d4 {
  strings:
    $key_15d4 = { 42 a6 [2] 70 84 [2] 76 b1 [2] 58 b1 [2] 67 ad }

  condition:
    any of them
}