rule TTP_XOR_WriteProcessMemory_75bb {
  strings:
    $key_75bb = { 22 c9 [2] 10 eb [2] 16 de [2] 38 de [2] 07 c2 }

  condition:
    any of them
}