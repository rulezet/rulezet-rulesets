rule TTP_XOR_WriteProcessMemory_8cbe {
  strings:
    $key_8cbe = { db cc [2] e9 ee [2] ef db [2] c1 db [2] fe c7 }

  condition:
    any of them
}