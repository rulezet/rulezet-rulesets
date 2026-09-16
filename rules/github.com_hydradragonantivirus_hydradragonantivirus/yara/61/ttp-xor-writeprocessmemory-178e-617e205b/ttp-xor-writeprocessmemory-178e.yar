rule TTP_XOR_WriteProcessMemory_178e {
  strings:
    $key_178e = { 40 fc [2] 72 de [2] 74 eb [2] 5a eb [2] 65 f7 }

  condition:
    any of them
}