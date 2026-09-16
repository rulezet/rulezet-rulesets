rule TTP_XOR_WriteProcessMemory_078e {
  strings:
    $key_078e = { 50 fc [2] 62 de [2] 64 eb [2] 4a eb [2] 75 f7 }

  condition:
    any of them
}