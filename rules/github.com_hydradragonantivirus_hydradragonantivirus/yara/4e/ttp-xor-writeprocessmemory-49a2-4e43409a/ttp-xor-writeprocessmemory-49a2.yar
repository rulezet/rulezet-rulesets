rule TTP_XOR_WriteProcessMemory_49a2 {
  strings:
    $key_49a2 = { 1e d0 [2] 2c f2 [2] 2a c7 [2] 04 c7 [2] 3b db }

  condition:
    any of them
}