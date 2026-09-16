rule TTP_XOR_WriteProcessMemory_d6bb {
  strings:
    $key_d6bb = { 81 c9 [2] b3 eb [2] b5 de [2] 9b de [2] a4 c2 }

  condition:
    any of them
}