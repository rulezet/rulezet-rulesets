rule TTP_XOR_WriteProcessMemory_15b0 {
  strings:
    $key_15b0 = { 42 c2 [2] 70 e0 [2] 76 d5 [2] 58 d5 [2] 67 c9 }

  condition:
    any of them
}