rule TTP_XOR_WriteProcessMemory_b2ac {
  strings:
    $key_b2ac = { e5 de [2] d7 fc [2] d1 c9 [2] ff c9 [2] c0 d5 }

  condition:
    any of them
}