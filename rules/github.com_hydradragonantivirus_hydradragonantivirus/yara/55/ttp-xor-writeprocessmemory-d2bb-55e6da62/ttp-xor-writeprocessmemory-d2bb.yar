rule TTP_XOR_WriteProcessMemory_d2bb {
  strings:
    $key_d2bb = { 85 c9 [2] b7 eb [2] b1 de [2] 9f de [2] a0 c2 }

  condition:
    any of them
}