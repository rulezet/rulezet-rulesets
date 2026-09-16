rule TTP_XOR_WriteProcessMemory_f8bb {
  strings:
    $key_f8bb = { af c9 [2] 9d eb [2] 9b de [2] b5 de [2] 8a c2 }

  condition:
    any of them
}