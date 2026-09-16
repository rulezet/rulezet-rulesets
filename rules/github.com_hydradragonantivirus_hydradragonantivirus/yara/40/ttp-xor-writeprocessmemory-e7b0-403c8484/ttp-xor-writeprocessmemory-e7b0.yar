rule TTP_XOR_WriteProcessMemory_e7b0 {
  strings:
    $key_e7b0 = { b0 c2 [2] 82 e0 [2] 84 d5 [2] aa d5 [2] 95 c9 }

  condition:
    any of them
}