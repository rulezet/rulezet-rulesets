rule TTP_XOR_WriteProcessMemory_a5ac {
  strings:
    $key_a5ac = { f2 de [2] c0 fc [2] c6 c9 [2] e8 c9 [2] d7 d5 }

  condition:
    any of them
}