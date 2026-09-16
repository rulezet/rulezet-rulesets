rule TTP_XOR_WriteProcessMemory_39a4 {
  strings:
    $key_39a4 = { 6e d6 [2] 5c f4 [2] 5a c1 [2] 74 c1 [2] 4b dd }

  condition:
    any of them
}