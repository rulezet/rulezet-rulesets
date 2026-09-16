rule TTP_XOR_WriteProcessMemory_51bb {
  strings:
    $key_51bb = { 06 c9 [2] 34 eb [2] 32 de [2] 1c de [2] 23 c2 }

  condition:
    any of them
}