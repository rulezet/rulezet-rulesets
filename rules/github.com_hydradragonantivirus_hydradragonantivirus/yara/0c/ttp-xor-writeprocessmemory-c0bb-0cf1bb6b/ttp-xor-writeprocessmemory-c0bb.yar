rule TTP_XOR_WriteProcessMemory_c0bb {
  strings:
    $key_c0bb = { 97 c9 [2] a5 eb [2] a3 de [2] 8d de [2] b2 c2 }

  condition:
    any of them
}