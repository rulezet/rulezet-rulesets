rule TTP_XOR_WriteProcessMemory_168e {
  strings:
    $key_168e = { 41 fc [2] 73 de [2] 75 eb [2] 5b eb [2] 64 f7 }

  condition:
    any of them
}