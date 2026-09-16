rule TTP_XOR_WriteProcessMemory_19a0 {
  strings:
    $key_19a0 = { 4e d2 [2] 7c f0 [2] 7a c5 [2] 54 c5 [2] 6b d9 }

  condition:
    any of them
}