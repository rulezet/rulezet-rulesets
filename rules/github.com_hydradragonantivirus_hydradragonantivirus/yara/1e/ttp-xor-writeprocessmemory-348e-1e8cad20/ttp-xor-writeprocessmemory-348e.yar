rule TTP_XOR_WriteProcessMemory_348e {
  strings:
    $key_348e = { 63 fc [2] 51 de [2] 57 eb [2] 79 eb [2] 46 f7 }

  condition:
    any of them
}