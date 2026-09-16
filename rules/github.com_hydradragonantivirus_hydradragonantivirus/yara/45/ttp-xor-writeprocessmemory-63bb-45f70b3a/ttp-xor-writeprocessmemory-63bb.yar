rule TTP_XOR_WriteProcessMemory_63bb {
  strings:
    $key_63bb = { 34 c9 [2] 06 eb [2] 00 de [2] 2e de [2] 11 c2 }

  condition:
    any of them
}