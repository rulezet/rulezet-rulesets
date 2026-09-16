rule TTP_XOR_WriteProcessMemory_70bb {
  strings:
    $key_70bb = { 27 c9 [2] 15 eb [2] 13 de [2] 3d de [2] 02 c2 }

  condition:
    any of them
}