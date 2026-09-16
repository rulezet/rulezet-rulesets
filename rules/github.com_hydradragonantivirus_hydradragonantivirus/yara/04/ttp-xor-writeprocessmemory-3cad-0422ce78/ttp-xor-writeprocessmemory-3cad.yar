rule TTP_XOR_WriteProcessMemory_3cad {
  strings:
    $key_3cad = { 6b df [2] 59 fd [2] 5f c8 [2] 71 c8 [2] 4e d4 }

  condition:
    any of them
}