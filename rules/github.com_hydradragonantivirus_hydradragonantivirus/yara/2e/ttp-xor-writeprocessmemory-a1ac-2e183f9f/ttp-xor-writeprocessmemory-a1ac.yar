rule TTP_XOR_WriteProcessMemory_a1ac {
  strings:
    $key_a1ac = { f6 de [2] c4 fc [2] c2 c9 [2] ec c9 [2] d3 d5 }

  condition:
    any of them
}