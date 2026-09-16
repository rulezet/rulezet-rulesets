rule TTP_XOR_WriteProcessMemory_62bb {
  strings:
    $key_62bb = { 35 c9 [2] 07 eb [2] 01 de [2] 2f de [2] 10 c2 }

  condition:
    any of them
}