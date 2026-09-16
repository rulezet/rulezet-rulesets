rule TTP_XOR_WriteProcessMemory_64bb {
  strings:
    $key_64bb = { 33 c9 [2] 01 eb [2] 07 de [2] 29 de [2] 16 c2 }

  condition:
    any of them
}