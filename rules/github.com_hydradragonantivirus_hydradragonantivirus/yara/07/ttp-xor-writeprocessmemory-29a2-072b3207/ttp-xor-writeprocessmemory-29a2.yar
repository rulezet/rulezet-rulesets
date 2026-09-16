rule TTP_XOR_WriteProcessMemory_29a2 {
  strings:
    $key_29a2 = { 7e d0 [2] 4c f2 [2] 4a c7 [2] 64 c7 [2] 5b db }

  condition:
    any of them
}