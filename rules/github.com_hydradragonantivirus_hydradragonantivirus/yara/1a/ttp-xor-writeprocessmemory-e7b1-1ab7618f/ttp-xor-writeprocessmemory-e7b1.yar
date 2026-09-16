rule TTP_XOR_WriteProcessMemory_e7b1 {
  strings:
    $key_e7b1 = { b0 c3 [2] 82 e1 [2] 84 d4 [2] aa d4 [2] 95 c8 }

  condition:
    any of them
}