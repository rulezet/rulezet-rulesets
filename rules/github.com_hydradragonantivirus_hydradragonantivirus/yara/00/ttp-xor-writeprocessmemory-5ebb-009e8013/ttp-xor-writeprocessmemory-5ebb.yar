rule TTP_XOR_WriteProcessMemory_5ebb {
  strings:
    $key_5ebb = { 09 c9 [2] 3b eb [2] 3d de [2] 13 de [2] 2c c2 }

  condition:
    any of them
}