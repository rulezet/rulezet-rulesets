rule TTP_XOR_WriteProcessMemory_0e9e {
  strings:
    $key_0e9e = { 59 ec [2] 6b ce [2] 6d fb [2] 43 fb [2] 7c e7 }

  condition:
    any of them
}