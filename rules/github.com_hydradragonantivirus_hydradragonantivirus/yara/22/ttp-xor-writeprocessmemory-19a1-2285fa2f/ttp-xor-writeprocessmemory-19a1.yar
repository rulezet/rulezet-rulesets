rule TTP_XOR_WriteProcessMemory_19a1 {
  strings:
    $key_19a1 = { 4e d3 [2] 7c f1 [2] 7a c4 [2] 54 c4 [2] 6b d8 }

  condition:
    any of them
}