rule TTP_XOR_WriteProcessMemory_1cad {
  strings:
    $key_1cad = { 4b df [2] 79 fd [2] 7f c8 [2] 51 c8 [2] 6e d4 }

  condition:
    any of them
}