rule TTP_XOR_WriteProcessMemory_09a5 {
  strings:
    $key_09a5 = { 5e d7 [2] 6c f5 [2] 6a c0 [2] 44 c0 [2] 7b dc }

  condition:
    any of them
}