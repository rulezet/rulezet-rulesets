rule TTP_XOR_WriteProcessMemory_13b0 {
  strings:
    $key_13b0 = { 44 c2 [2] 76 e0 [2] 70 d5 [2] 5e d5 [2] 61 c9 }

  condition:
    any of them
}