rule TTP_XOR_WriteProcessMemory_639e {
  strings:
    $key_639e = { 34 ec [2] 06 ce [2] 00 fb [2] 2e fb [2] 11 e7 }

  condition:
    any of them
}