rule TTP_XOR_WriteProcessMemory_19a2 {
  strings:
    $key_19a2 = { 4e d0 [2] 7c f2 [2] 7a c7 [2] 54 c7 [2] 6b db }

  condition:
    any of them
}