rule TTP_XOR_WriteProcessMemory_658e {
  strings:
    $key_658e = { 32 fc [2] 00 de [2] 06 eb [2] 28 eb [2] 17 f7 }

  condition:
    any of them
}