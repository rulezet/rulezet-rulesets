rule TTP_XOR_WriteProcessMemory_60ac {
  strings:
    $key_60ac = { 37 de [2] 05 fc [2] 03 c9 [2] 2d c9 [2] 12 d5 }

  condition:
    any of them
}