rule TTP_XOR_WriteProcessMemory_e08e {
  strings:
    $key_e08e = { b7 fc [2] 85 de [2] 83 eb [2] ad eb [2] 92 f7 }

  condition:
    any of them
}