rule TTP_XOR_WriteProcessMemory_1564 {
  strings:
    $key_1564 = { 42 16 [2] 70 34 [2] 76 01 [2] 58 01 [2] 67 1d }

  condition:
    any of them
}