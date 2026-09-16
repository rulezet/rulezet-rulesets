rule TTP_XOR_WriteProcessMemory_59a4 {
  strings:
    $key_59a4 = { 0e d6 [2] 3c f4 [2] 3a c1 [2] 14 c1 [2] 2b dd }

  condition:
    any of them
}