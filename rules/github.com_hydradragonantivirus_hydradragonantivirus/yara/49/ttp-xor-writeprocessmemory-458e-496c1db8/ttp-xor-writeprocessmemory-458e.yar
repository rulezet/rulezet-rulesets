rule TTP_XOR_WriteProcessMemory_458e {
  strings:
    $key_458e = { 12 fc [2] 20 de [2] 26 eb [2] 08 eb [2] 37 f7 }

  condition:
    any of them
}