rule TTP_XOR_WriteProcessMemory_42bb {
  strings:
    $key_42bb = { 15 c9 [2] 27 eb [2] 21 de [2] 0f de [2] 30 c2 }

  condition:
    any of them
}