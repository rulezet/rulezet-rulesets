rule TTP_XOR_WriteProcessMemory_01bb {
  strings:
    $key_01bb = { 56 c9 [2] 64 eb [2] 62 de [2] 4c de [2] 73 c2 }

  condition:
    any of them
}