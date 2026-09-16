rule TTP_XOR_WriteProcessMemory_1561 {
  strings:
    $key_1561 = { 42 13 [2] 70 31 [2] 76 04 [2] 58 04 [2] 67 18 }

  condition:
    any of them
}