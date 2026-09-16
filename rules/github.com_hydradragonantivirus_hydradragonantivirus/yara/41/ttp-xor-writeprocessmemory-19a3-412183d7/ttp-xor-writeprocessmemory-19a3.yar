rule TTP_XOR_WriteProcessMemory_19a3 {
  strings:
    $key_19a3 = { 4e d1 [2] 7c f3 [2] 7a c6 [2] 54 c6 [2] 6b da }

  condition:
    any of them
}