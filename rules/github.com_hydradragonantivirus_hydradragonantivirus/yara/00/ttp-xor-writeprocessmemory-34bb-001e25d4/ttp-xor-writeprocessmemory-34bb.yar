rule TTP_XOR_WriteProcessMemory_34bb {
  strings:
    $key_34bb = { 63 c9 [2] 51 eb [2] 57 de [2] 79 de [2] 46 c2 }

  condition:
    any of them
}