rule TTP_XOR_WriteProcessMemory_7ba0 {
  strings:
    $key_7ba0 = { 2c d2 [2] 1e f0 [2] 18 c5 [2] 36 c5 [2] 09 d9 }

  condition:
    any of them
}