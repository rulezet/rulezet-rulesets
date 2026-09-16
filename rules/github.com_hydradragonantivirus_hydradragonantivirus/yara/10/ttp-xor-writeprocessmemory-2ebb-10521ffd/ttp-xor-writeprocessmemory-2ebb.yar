rule TTP_XOR_WriteProcessMemory_2ebb {
  strings:
    $key_2ebb = { 79 c9 [2] 4b eb [2] 4d de [2] 63 de [2] 5c c2 }

  condition:
    any of them
}