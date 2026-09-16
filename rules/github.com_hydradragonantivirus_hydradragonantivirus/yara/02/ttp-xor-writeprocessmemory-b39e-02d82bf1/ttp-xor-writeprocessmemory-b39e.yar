rule TTP_XOR_WriteProcessMemory_b39e {
  strings:
    $key_b39e = { e4 ec [2] d6 ce [2] d0 fb [2] fe fb [2] c1 e7 }

  condition:
    any of them
}