rule TTP_XOR_WriteProcessMemory_67ac {
  strings:
    $key_67ac = { 30 de [2] 02 fc [2] 04 c9 [2] 2a c9 [2] 15 d5 }

  condition:
    any of them
}