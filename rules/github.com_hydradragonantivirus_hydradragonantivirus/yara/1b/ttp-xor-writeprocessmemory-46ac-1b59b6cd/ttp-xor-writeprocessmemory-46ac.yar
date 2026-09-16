rule TTP_XOR_WriteProcessMemory_46ac {
  strings:
    $key_46ac = { 11 de [2] 23 fc [2] 25 c9 [2] 0b c9 [2] 34 d5 }

  condition:
    any of them
}