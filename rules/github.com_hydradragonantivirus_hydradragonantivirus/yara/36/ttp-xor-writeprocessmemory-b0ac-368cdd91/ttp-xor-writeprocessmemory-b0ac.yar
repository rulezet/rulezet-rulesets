rule TTP_XOR_WriteProcessMemory_b0ac {
  strings:
    $key_b0ac = { e7 de [2] d5 fc [2] d3 c9 [2] fd c9 [2] c2 d5 }

  condition:
    any of them
}