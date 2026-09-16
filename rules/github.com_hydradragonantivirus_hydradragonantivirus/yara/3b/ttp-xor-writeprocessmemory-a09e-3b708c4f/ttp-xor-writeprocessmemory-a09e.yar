rule TTP_XOR_WriteProcessMemory_a09e {
  strings:
    $key_a09e = { f7 ec [2] c5 ce [2] c3 fb [2] ed fb [2] d2 e7 }

  condition:
    any of them
}