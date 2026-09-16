rule TTP_XOR_WriteProcessMemory_23b0 {
  strings:
    $key_23b0 = { 74 c2 [2] 46 e0 [2] 40 d5 [2] 6e d5 [2] 51 c9 }

  condition:
    any of them
}