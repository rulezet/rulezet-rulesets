rule TTP_XOR_WriteProcessMemory_328e {
  strings:
    $key_328e = { 65 fc [2] 57 de [2] 51 eb [2] 7f eb [2] 40 f7 }

  condition:
    any of them
}