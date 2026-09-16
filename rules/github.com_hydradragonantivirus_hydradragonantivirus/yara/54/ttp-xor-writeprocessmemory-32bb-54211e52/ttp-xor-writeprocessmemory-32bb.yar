rule TTP_XOR_WriteProcessMemory_32bb {
  strings:
    $key_32bb = { 65 c9 [2] 57 eb [2] 51 de [2] 7f de [2] 40 c2 }

  condition:
    any of them
}