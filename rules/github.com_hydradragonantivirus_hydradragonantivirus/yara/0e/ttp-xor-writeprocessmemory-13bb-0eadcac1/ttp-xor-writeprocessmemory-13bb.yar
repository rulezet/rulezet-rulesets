rule TTP_XOR_WriteProcessMemory_13bb {
  strings:
    $key_13bb = { 44 c9 [2] 76 eb [2] 70 de [2] 5e de [2] 61 c2 }

  condition:
    any of them
}