rule TTP_XOR_WriteProcessMemory_49a1 {
  strings:
    $key_49a1 = { 1e d3 [2] 2c f1 [2] 2a c4 [2] 04 c4 [2] 3b d8 }

  condition:
    any of them
}