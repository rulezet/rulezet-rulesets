rule TTP_XOR_WriteProcessMemory_339e {
  strings:
    $key_339e = { 64 ec [2] 56 ce [2] 50 fb [2] 7e fb [2] 41 e7 }

  condition:
    any of them
}