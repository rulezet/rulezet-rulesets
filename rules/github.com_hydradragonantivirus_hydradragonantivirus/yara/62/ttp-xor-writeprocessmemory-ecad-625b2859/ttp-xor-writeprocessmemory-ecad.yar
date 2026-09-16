rule TTP_XOR_WriteProcessMemory_ecad {
  strings:
    $key_ecad = { bb df [2] 89 fd [2] 8f c8 [2] a1 c8 [2] 9e d4 }

  condition:
    any of them
}