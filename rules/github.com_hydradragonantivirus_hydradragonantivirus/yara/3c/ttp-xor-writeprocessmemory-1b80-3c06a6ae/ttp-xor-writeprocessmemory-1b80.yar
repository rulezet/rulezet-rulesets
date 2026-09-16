rule TTP_XOR_WriteProcessMemory_1b80 {
  strings:
    $key_1b80 = { 4c f2 [2] 7e d0 [2] 78 e5 [2] 56 e5 [2] 69 f9 }

  condition:
    any of them
}