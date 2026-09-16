rule TTP_XOR_WriteProcessMemory_5e9e {
  strings:
    $key_5e9e = { 09 ec [2] 3b ce [2] 3d fb [2] 13 fb [2] 2c e7 }

  condition:
    any of them
}