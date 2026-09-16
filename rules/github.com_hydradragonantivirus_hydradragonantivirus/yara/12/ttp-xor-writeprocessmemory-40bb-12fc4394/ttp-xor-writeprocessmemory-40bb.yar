rule TTP_XOR_WriteProcessMemory_40bb {
  strings:
    $key_40bb = { 17 c9 [2] 25 eb [2] 23 de [2] 0d de [2] 32 c2 }

  condition:
    any of them
}