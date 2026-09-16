rule TTP_XOR_WriteProcessMemory_d1bb {
  strings:
    $key_d1bb = { 86 c9 [2] b4 eb [2] b2 de [2] 9c de [2] a3 c2 }

  condition:
    any of them
}