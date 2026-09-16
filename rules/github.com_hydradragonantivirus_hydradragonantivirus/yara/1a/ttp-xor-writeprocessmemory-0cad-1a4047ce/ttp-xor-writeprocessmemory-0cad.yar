rule TTP_XOR_WriteProcessMemory_0cad {
  strings:
    $key_0cad = { 5b df [2] 69 fd [2] 6f c8 [2] 41 c8 [2] 7e d4 }

  condition:
    any of them
}