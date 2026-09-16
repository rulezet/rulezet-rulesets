rule TTP_XOR_WriteProcessMemory_72ac {
  strings:
    $key_72ac = { 25 de [2] 17 fc [2] 11 c9 [2] 3f c9 [2] 00 d5 }

  condition:
    any of them
}