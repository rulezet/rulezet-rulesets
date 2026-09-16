rule TTP_XOR_WriteProcessMemory_90bb {
  strings:
    $key_90bb = { c7 c9 [2] f5 eb [2] f3 de [2] dd de [2] e2 c2 }

  condition:
    any of them
}