rule TTP_XOR_WriteProcessMemory_7ba7 {
  strings:
    $key_7ba7 = { 2c d5 [2] 1e f7 [2] 18 c2 [2] 36 c2 [2] 09 de }

  condition:
    any of them
}