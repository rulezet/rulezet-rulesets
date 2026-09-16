rule TTP_XOR_WriteProcessMemory_42b1 {
  strings:
    $key_42b1 = { 15 c3 [2] 27 e1 [2] 21 d4 [2] 0f d4 [2] 30 c8 }

  condition:
    any of them
}