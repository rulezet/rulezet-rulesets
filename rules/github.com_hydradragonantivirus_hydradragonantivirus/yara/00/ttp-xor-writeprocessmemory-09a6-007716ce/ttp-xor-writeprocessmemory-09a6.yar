rule TTP_XOR_WriteProcessMemory_09a6 {
  strings:
    $key_09a6 = { 5e d4 [2] 6c f6 [2] 6a c3 [2] 44 c3 [2] 7b df }

  condition:
    any of them
}