rule TTP_XOR_WriteProcessMemory_f58e {
  strings:
    $key_f58e = { a2 fc [2] 90 de [2] 96 eb [2] b8 eb [2] 87 f7 }

  condition:
    any of them
}