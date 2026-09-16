rule TTP_XOR_WriteProcessMemory_90ac {
  strings:
    $key_90ac = { c7 de [2] f5 fc [2] f3 c9 [2] dd c9 [2] e2 d5 }

  condition:
    any of them
}