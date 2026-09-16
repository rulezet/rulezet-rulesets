rule TTP_XOR_WriteProcessMemory_778e {
  strings:
    $key_778e = { 20 fc [2] 12 de [2] 14 eb [2] 3a eb [2] 05 f7 }

  condition:
    any of them
}