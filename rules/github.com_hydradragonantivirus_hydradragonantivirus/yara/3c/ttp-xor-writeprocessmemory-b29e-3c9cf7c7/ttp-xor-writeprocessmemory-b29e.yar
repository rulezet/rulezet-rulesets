rule TTP_XOR_WriteProcessMemory_b29e {
  strings:
    $key_b29e = { e5 ec [2] d7 ce [2] d1 fb [2] ff fb [2] c0 e7 }

  condition:
    any of them
}