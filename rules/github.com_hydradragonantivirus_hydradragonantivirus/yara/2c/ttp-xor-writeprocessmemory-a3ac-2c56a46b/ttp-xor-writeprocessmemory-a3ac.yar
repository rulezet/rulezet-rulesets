rule TTP_XOR_WriteProcessMemory_a3ac {
  strings:
    $key_a3ac = { f4 de [2] c6 fc [2] c0 c9 [2] ee c9 [2] d1 d5 }

  condition:
    any of them
}