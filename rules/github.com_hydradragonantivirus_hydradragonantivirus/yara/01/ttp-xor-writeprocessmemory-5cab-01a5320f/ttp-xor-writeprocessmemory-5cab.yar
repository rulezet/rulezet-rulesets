rule TTP_XOR_WriteProcessMemory_5cab {
  strings:
    $key_5cab = { 0b d9 [2] 39 fb [2] 3f ce [2] 11 ce [2] 2e d2 }

  condition:
    any of them
}