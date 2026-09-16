rule TTP_XOR_WriteProcessMemory_39a5 {
  strings:
    $key_39a5 = { 6e d7 [2] 5c f5 [2] 5a c0 [2] 74 c0 [2] 4b dc }

  condition:
    any of them
}