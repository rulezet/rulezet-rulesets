rule TTP_XOR_WriteProcessMemory_febb {
  strings:
    $key_febb = { a9 c9 [2] 9b eb [2] 9d de [2] b3 de [2] 8c c2 }

  condition:
    any of them
}