rule TTP_XOR_WriteProcessMemory_03bb {
  strings:
    $key_03bb = { 54 c9 [2] 66 eb [2] 60 de [2] 4e de [2] 71 c2 }

  condition:
    any of them
}