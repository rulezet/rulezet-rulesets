rule TTP_XOR_WriteProcessMemory_c4bb {
  strings:
    $key_c4bb = { 93 c9 [2] a1 eb [2] a7 de [2] 89 de [2] b6 c2 }

  condition:
    any of them
}