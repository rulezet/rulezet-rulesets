rule TTP_XOR_WriteProcessMemory_e1ac {
  strings:
    $key_e1ac = { b6 de [2] 84 fc [2] 82 c9 [2] ac c9 [2] 93 d5 }

  condition:
    any of them
}