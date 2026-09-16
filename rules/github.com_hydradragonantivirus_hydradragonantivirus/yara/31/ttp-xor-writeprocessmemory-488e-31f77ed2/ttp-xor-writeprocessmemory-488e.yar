rule TTP_XOR_WriteProcessMemory_488e {
  strings:
    $key_488e = { 1f fc [2] 2d de [2] 2b eb [2] 05 eb [2] 3a f7 }

  condition:
    any of them
}