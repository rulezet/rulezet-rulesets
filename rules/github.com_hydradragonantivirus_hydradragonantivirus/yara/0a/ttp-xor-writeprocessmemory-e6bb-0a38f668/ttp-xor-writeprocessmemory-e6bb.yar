rule TTP_XOR_WriteProcessMemory_e6bb {
  strings:
    $key_e6bb = { b1 c9 [2] 83 eb [2] 85 de [2] ab de [2] 94 c2 }

  condition:
    any of them
}