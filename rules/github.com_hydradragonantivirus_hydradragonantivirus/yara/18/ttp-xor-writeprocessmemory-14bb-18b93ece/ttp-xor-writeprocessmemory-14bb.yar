rule TTP_XOR_WriteProcessMemory_14bb {
  strings:
    $key_14bb = { 43 c9 [2] 71 eb [2] 77 de [2] 59 de [2] 66 c2 }

  condition:
    any of them
}