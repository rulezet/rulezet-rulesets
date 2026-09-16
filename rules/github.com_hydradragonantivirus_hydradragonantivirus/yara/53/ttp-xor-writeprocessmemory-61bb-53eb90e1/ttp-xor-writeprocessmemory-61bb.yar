rule TTP_XOR_WriteProcessMemory_61bb {
  strings:
    $key_61bb = { 36 c9 [2] 04 eb [2] 02 de [2] 2c de [2] 13 c2 }

  condition:
    any of them
}