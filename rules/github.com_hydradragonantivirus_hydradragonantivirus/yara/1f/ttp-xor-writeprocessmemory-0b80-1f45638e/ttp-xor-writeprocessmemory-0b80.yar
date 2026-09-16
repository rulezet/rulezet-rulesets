rule TTP_XOR_WriteProcessMemory_0b80 {
  strings:
    $key_0b80 = { 5c f2 [2] 6e d0 [2] 68 e5 [2] 46 e5 [2] 79 f9 }

  condition:
    any of them
}