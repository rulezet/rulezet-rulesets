rule TTP_XOR_WriteProcessMemory_63ac {
  strings:
    $key_63ac = { 34 de [2] 06 fc [2] 00 c9 [2] 2e c9 [2] 11 d5 }

  condition:
    any of them
}