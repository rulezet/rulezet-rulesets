rule TTP_XOR_WriteProcessMemory_21ac {
  strings:
    $key_21ac = { 76 de [2] 44 fc [2] 42 c9 [2] 6c c9 [2] 53 d5 }

  condition:
    any of them
}