rule TTP_XOR_WriteProcessMemory_24bb {
  strings:
    $key_24bb = { 73 c9 [2] 41 eb [2] 47 de [2] 69 de [2] 56 c2 }

  condition:
    any of them
}