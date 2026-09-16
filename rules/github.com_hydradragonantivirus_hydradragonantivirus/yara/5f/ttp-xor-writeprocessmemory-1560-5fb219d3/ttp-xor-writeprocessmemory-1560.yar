rule TTP_XOR_WriteProcessMemory_1560 {
  strings:
    $key_1560 = { 42 12 [2] 70 30 [2] 76 05 [2] 58 05 [2] 67 19 }

  condition:
    any of them
}