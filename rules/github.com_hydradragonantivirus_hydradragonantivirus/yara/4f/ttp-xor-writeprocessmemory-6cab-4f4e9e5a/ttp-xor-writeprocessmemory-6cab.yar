rule TTP_XOR_WriteProcessMemory_6cab {
  strings:
    $key_6cab = { 3b d9 [2] 09 fb [2] 0f ce [2] 21 ce [2] 1e d2 }

  condition:
    any of them
}