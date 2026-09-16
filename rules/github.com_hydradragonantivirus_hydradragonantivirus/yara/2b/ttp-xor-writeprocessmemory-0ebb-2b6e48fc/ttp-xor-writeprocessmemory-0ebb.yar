rule TTP_XOR_WriteProcessMemory_0ebb {
  strings:
    $key_0ebb = { 59 c9 [2] 6b eb [2] 6d de [2] 43 de [2] 7c c2 }

  condition:
    any of them
}