rule TTP_XOR_WriteProcessMemory_57ac {
  strings:
    $key_57ac = { 00 de [2] 32 fc [2] 34 c9 [2] 1a c9 [2] 25 d5 }

  condition:
    any of them
}