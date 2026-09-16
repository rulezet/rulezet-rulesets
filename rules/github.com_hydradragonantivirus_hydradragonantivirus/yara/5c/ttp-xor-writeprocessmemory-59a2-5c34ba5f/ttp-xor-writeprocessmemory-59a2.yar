rule TTP_XOR_WriteProcessMemory_59a2 {
  strings:
    $key_59a2 = { 0e d0 [2] 3c f2 [2] 3a c7 [2] 14 c7 [2] 2b db }

  condition:
    any of them
}