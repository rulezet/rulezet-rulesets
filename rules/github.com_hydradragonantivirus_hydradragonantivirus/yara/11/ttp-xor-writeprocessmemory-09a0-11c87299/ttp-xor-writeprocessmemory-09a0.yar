rule TTP_XOR_WriteProcessMemory_09a0 {
  strings:
    $key_09a0 = { 5e d2 [2] 6c f0 [2] 6a c5 [2] 44 c5 [2] 7b d9 }

  condition:
    any of them
}