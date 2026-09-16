rule TTP_XOR_WriteProcessMemory_21b0 {
  strings:
    $key_21b0 = { 76 c2 [2] 44 e0 [2] 42 d5 [2] 6c d5 [2] 53 c9 }

  condition:
    any of them
}