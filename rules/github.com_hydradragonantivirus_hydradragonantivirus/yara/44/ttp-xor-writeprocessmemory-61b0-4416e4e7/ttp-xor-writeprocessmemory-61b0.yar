rule TTP_XOR_WriteProcessMemory_61b0 {
  strings:
    $key_61b0 = { 36 c2 [2] 04 e0 [2] 02 d5 [2] 2c d5 [2] 13 c9 }

  condition:
    any of them
}