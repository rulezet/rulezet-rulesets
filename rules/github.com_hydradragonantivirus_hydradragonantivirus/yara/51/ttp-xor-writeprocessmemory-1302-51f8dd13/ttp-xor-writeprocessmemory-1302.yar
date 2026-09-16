rule TTP_XOR_WriteProcessMemory_1302 {
  strings:
    $key_1302 = { 44 70 [2] 76 52 [2] 70 67 [2] 5e 67 [2] 61 7b }

  condition:
    any of them
}