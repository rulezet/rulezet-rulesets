rule TTP_XOR_WriteProcessMemory_a69e {
  strings:
    $key_a69e = { f1 ec [2] c3 ce [2] c5 fb [2] eb fb [2] d4 e7 }

  condition:
    any of them
}