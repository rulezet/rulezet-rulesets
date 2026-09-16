rule TTP_XOR_WriteProcessMemory_8c8e {
  strings:
    $key_8c8e = { db fc [2] e9 de [2] ef eb [2] c1 eb [2] fe f7 }

  condition:
    any of them
}