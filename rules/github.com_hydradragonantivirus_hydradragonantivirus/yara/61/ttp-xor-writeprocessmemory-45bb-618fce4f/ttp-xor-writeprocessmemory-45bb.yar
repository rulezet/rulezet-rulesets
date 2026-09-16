rule TTP_XOR_WriteProcessMemory_45bb {
  strings:
    $key_45bb = { 12 c9 [2] 20 eb [2] 26 de [2] 08 de [2] 37 c2 }

  condition:
    any of them
}