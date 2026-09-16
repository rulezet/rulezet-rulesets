rule TTP_XOR_WriteProcessMemory_a58e {
  strings:
    $key_a58e = { f2 fc [2] c0 de [2] c6 eb [2] e8 eb [2] d7 f7 }

  condition:
    any of them
}