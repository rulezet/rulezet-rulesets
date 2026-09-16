rule TTP_XOR_WriteProcessMemory_5db0 {
  strings:
    $key_5db0 = { 0a c2 [2] 38 e0 [2] 3e d5 [2] 10 d5 [2] 2f c9 }

  condition:
    any of them
}