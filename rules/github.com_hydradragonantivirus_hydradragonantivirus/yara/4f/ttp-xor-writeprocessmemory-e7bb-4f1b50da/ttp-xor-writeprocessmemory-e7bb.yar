rule TTP_XOR_WriteProcessMemory_e7bb {
  strings:
    $key_e7bb = { b0 c9 [2] 82 eb [2] 84 de [2] aa de [2] 95 c2 }

  condition:
    any of them
}