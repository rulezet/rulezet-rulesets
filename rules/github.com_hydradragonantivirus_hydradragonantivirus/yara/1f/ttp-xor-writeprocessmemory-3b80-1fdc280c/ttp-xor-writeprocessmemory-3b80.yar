rule TTP_XOR_WriteProcessMemory_3b80 {
  strings:
    $key_3b80 = { 6c f2 [2] 5e d0 [2] 58 e5 [2] 76 e5 [2] 49 f9 }

  condition:
    any of them
}