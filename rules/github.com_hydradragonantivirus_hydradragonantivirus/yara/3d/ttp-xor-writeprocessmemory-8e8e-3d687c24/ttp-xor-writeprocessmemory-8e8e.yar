rule TTP_XOR_WriteProcessMemory_8e8e {
  strings:
    $key_8e8e = { d9 fc [2] eb de [2] ed eb [2] c3 eb [2] fc f7 }

  condition:
    any of them
}