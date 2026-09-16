rule TTP_XOR_WriteProcessMemory_57bb {
  strings:
    $key_57bb = { 00 c9 [2] 32 eb [2] 34 de [2] 1a de [2] 25 c2 }

  condition:
    any of them
}