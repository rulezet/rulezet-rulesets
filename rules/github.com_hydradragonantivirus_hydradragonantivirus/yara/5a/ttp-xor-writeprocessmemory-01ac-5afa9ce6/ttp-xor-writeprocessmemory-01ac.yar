rule TTP_XOR_WriteProcessMemory_01ac {
  strings:
    $key_01ac = { 56 de [2] 64 fc [2] 62 c9 [2] 4c c9 [2] 73 d5 }

  condition:
    any of them
}