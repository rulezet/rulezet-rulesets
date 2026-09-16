rule TTP_XOR_WriteProcessMemory_b5ac {
  strings:
    $key_b5ac = { e2 de [2] d0 fc [2] d6 c9 [2] f8 c9 [2] c7 d5 }

  condition:
    any of them
}