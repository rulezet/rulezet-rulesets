rule TTP_XOR_WriteProcessMemory_418e {
  strings:
    $key_418e = { 16 fc [2] 24 de [2] 22 eb [2] 0c eb [2] 33 f7 }

  condition:
    any of them
}