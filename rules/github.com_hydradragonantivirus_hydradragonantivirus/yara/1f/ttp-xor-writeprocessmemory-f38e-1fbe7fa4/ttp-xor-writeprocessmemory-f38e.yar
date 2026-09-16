rule TTP_XOR_WriteProcessMemory_f38e {
  strings:
    $key_f38e = { a4 fc [2] 96 de [2] 90 eb [2] be eb [2] 81 f7 }

  condition:
    any of them
}