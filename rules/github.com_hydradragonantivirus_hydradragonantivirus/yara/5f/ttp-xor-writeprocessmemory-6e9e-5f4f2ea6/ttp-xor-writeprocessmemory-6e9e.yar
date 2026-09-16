rule TTP_XOR_WriteProcessMemory_6e9e {
  strings:
    $key_6e9e = { 39 ec [2] 0b ce [2] 0d fb [2] 23 fb [2] 1c e7 }

  condition:
    any of them
}