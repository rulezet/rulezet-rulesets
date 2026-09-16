rule TTP_XOR_WriteProcessMemory_a78e {
  strings:
    $key_a78e = { f0 fc [2] c2 de [2] c4 eb [2] ea eb [2] d5 f7 }

  condition:
    any of them
}