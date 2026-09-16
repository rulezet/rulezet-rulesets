rule TTP_XOR_WriteProcessMemory_47ac {
  strings:
    $key_47ac = { 10 de [2] 22 fc [2] 24 c9 [2] 0a c9 [2] 35 d5 }

  condition:
    any of them
}