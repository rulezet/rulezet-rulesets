rule TTP_XOR_WriteProcessMemory_678e {
  strings:
    $key_678e = { 30 fc [2] 02 de [2] 04 eb [2] 2a eb [2] 15 f7 }

  condition:
    any of them
}