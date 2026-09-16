rule TTP_XOR_WriteProcessMemory_73ac {
  strings:
    $key_73ac = { 24 de [2] 16 fc [2] 10 c9 [2] 3e c9 [2] 01 d5 }

  condition:
    any of them
}