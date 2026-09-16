rule TTP_XOR_WriteProcessMemory_a2ac {
  strings:
    $key_a2ac = { f5 de [2] c7 fc [2] c1 c9 [2] ef c9 [2] d0 d5 }

  condition:
    any of them
}