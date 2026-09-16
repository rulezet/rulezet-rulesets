rule TTP_XOR_WriteProcessMemory_77ac {
  strings:
    $key_77ac = { 20 de [2] 12 fc [2] 14 c9 [2] 3a c9 [2] 05 d5 }

  condition:
    any of them
}