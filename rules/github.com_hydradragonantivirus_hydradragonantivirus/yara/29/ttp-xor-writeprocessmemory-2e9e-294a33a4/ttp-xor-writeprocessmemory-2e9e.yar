rule TTP_XOR_WriteProcessMemory_2e9e {
  strings:
    $key_2e9e = { 79 ec [2] 4b ce [2] 4d fb [2] 63 fb [2] 5c e7 }

  condition:
    any of them
}