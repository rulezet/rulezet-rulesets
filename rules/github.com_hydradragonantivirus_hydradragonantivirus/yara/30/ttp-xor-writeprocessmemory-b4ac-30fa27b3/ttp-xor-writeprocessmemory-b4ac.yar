rule TTP_XOR_WriteProcessMemory_b4ac {
  strings:
    $key_b4ac = { e3 de [2] d1 fc [2] d7 c9 [2] f9 c9 [2] c6 d5 }

  condition:
    any of them
}