rule TTP_XOR_WriteProcessMemory_408e {
  strings:
    $key_408e = { 17 fc [2] 25 de [2] 23 eb [2] 0d eb [2] 32 f7 }

  condition:
    any of them
}