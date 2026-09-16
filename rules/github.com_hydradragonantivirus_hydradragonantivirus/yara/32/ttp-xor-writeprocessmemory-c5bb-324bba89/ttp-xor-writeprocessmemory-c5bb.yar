rule TTP_XOR_WriteProcessMemory_c5bb {
  strings:
    $key_c5bb = { 92 c9 [2] a0 eb [2] a6 de [2] 88 de [2] b7 c2 }

  condition:
    any of them
}