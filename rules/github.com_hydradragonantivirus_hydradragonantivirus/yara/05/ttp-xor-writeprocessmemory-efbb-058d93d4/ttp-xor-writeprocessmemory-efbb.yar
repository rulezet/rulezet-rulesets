rule TTP_XOR_WriteProcessMemory_efbb {
  strings:
    $key_efbb = { b8 c9 [2] 8a eb [2] 8c de [2] a2 de [2] 9d c2 }

  condition:
    any of them
}