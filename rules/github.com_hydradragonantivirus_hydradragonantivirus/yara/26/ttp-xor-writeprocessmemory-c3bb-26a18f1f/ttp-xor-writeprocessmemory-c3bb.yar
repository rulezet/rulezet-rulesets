rule TTP_XOR_WriteProcessMemory_c3bb {
  strings:
    $key_c3bb = { 94 c9 [2] a6 eb [2] a0 de [2] 8e de [2] b1 c2 }

  condition:
    any of them
}