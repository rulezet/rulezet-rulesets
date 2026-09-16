rule TTP_XOR_WriteProcessMemory_e0ac {
  strings:
    $key_e0ac = { b7 de [2] 85 fc [2] 83 c9 [2] ad c9 [2] 92 d5 }

  condition:
    any of them
}