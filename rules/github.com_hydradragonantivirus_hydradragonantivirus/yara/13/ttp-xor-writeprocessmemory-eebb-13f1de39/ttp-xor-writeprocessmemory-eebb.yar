rule TTP_XOR_WriteProcessMemory_eebb {
  strings:
    $key_eebb = { b9 c9 [2] 8b eb [2] 8d de [2] a3 de [2] 9c c2 }

  condition:
    any of them
}