rule TTP_XOR_WriteProcessMemory_f0bb {
  strings:
    $key_f0bb = { a7 c9 [2] 95 eb [2] 93 de [2] bd de [2] 82 c2 }

  condition:
    any of them
}