rule TTP_XOR_WriteProcessMemory_25ac {
  strings:
    $key_25ac = { 72 de [2] 40 fc [2] 46 c9 [2] 68 c9 [2] 57 d5 }

  condition:
    any of them
}