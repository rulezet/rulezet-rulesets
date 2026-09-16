rule TTP_XOR_WriteProcessMemory_76bb {
  strings:
    $key_76bb = { 21 c9 [2] 13 eb [2] 15 de [2] 3b de [2] 04 c2 }

  condition:
    any of them
}