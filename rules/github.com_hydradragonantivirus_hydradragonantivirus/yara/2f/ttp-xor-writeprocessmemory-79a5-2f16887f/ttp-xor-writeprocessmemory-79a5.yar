rule TTP_XOR_WriteProcessMemory_79a5 {
  strings:
    $key_79a5 = { 2e d7 [2] 1c f5 [2] 1a c0 [2] 34 c0 [2] 0b dc }

  condition:
    any of them
}