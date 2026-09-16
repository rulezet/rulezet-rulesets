rule TTP_XOR_WriteProcessMemory_1591 {
  strings:
    $key_1591 = { 42 e3 [2] 70 c1 [2] 76 f4 [2] 58 f4 [2] 67 e8 }

  condition:
    any of them
}