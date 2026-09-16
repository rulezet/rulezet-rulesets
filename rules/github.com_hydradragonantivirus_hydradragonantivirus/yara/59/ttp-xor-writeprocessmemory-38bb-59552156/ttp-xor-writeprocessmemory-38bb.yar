rule TTP_XOR_WriteProcessMemory_38bb {
  strings:
    $key_38bb = { 6f c9 [2] 5d eb [2] 5b de [2] 75 de [2] 4a c2 }

  condition:
    any of them
}