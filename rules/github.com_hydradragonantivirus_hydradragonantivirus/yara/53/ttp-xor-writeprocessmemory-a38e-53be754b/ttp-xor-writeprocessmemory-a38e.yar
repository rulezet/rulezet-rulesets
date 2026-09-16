rule TTP_XOR_WriteProcessMemory_a38e {
  strings:
    $key_a38e = { f4 fc [2] c6 de [2] c0 eb [2] ee eb [2] d1 f7 }

  condition:
    any of them
}