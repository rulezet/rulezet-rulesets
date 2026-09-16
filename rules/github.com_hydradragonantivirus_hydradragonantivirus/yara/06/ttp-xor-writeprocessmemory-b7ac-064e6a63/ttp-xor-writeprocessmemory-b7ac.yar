rule TTP_XOR_WriteProcessMemory_b7ac {
  strings:
    $key_b7ac = { e0 de [2] d2 fc [2] d4 c9 [2] fa c9 [2] c5 d5 }

  condition:
    any of them
}