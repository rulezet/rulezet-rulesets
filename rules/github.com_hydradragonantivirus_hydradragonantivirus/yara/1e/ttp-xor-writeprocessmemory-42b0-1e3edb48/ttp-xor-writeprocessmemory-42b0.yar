rule TTP_XOR_WriteProcessMemory_42b0 {
  strings:
    $key_42b0 = { 15 c2 [2] 27 e0 [2] 21 d5 [2] 0f d5 [2] 30 c9 }

  condition:
    any of them
}