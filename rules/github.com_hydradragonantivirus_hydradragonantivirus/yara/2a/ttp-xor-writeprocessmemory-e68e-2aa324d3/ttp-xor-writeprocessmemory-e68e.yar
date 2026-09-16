rule TTP_XOR_WriteProcessMemory_e68e {
  strings:
    $key_e68e = { b1 fc [2] 83 de [2] 85 eb [2] ab eb [2] 94 f7 }

  condition:
    any of them
}