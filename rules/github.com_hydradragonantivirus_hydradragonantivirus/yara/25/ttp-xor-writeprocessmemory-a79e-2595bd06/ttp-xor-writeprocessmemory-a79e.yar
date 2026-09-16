rule TTP_XOR_WriteProcessMemory_a79e {
  strings:
    $key_a79e = { f0 ec [2] c2 ce [2] c4 fb [2] ea fb [2] d5 e7 }

  condition:
    any of them
}