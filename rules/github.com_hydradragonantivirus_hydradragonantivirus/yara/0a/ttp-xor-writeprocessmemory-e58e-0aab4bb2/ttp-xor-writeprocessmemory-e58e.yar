rule TTP_XOR_WriteProcessMemory_e58e {
  strings:
    $key_e58e = { b2 fc [2] 80 de [2] 86 eb [2] a8 eb [2] 97 f7 }

  condition:
    any of them
}