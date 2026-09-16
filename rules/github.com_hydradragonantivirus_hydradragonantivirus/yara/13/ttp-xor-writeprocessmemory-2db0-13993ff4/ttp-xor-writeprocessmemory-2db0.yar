rule TTP_XOR_WriteProcessMemory_2db0 {
  strings:
    $key_2db0 = { 7a c2 [2] 48 e0 [2] 4e d5 [2] 60 d5 [2] 5f c9 }

  condition:
    any of them
}