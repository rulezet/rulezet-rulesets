rule TTP_XOR_WriteProcessMemory_7ba6 {
  strings:
    $key_7ba6 = { 2c d4 [2] 1e f6 [2] 18 c3 [2] 36 c3 [2] 09 df }

  condition:
    any of them
}