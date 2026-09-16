rule TTP_XOR_WriteProcessMemory_f3bb {
  strings:
    $key_f3bb = { a4 c9 [2] 96 eb [2] 90 de [2] be de [2] 81 c2 }

  condition:
    any of them
}