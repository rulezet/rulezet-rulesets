rule TTP_XOR_WriteProcessMemory_39a6 {
  strings:
    $key_39a6 = { 6e d4 [2] 5c f6 [2] 5a c3 [2] 74 c3 [2] 4b df }

  condition:
    any of them
}