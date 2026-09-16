rule TTP_XOR_WriteProcessMemory_21bb {
  strings:
    $key_21bb = { 76 c9 [2] 44 eb [2] 42 de [2] 6c de [2] 53 c2 }

  condition:
    any of them
}