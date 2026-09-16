rule TTP_XOR_WriteProcessMemory_53b1 {
  strings:
    $key_53b1 = { 04 c3 [2] 36 e1 [2] 30 d4 [2] 1e d4 [2] 21 c8 }

  condition:
    any of them
}