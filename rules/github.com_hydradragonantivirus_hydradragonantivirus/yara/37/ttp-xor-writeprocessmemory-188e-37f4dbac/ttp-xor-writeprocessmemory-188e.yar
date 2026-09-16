rule TTP_XOR_WriteProcessMemory_188e {
  strings:
    $key_188e = { 4f fc [2] 7d de [2] 7b eb [2] 55 eb [2] 6a f7 }

  condition:
    any of them
}