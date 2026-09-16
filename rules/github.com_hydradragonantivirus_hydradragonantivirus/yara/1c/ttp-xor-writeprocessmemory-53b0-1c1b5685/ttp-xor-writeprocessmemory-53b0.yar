rule TTP_XOR_WriteProcessMemory_53b0 {
  strings:
    $key_53b0 = { 04 c2 [2] 36 e0 [2] 30 d5 [2] 1e d5 [2] 21 c9 }

  condition:
    any of them
}