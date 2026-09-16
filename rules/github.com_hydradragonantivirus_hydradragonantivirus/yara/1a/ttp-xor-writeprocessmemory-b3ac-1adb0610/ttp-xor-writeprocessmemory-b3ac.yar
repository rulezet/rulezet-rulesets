rule TTP_XOR_WriteProcessMemory_b3ac {
  strings:
    $key_b3ac = { e4 de [2] d6 fc [2] d0 c9 [2] fe c9 [2] c1 d5 }

  condition:
    any of them
}