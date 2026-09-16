rule TTP_XOR_WriteProcessMemory_00bb {
  strings:
    $key_00bb = { 57 c9 [2] 65 eb [2] 63 de [2] 4d de [2] 72 c2 }

  condition:
    any of them
}