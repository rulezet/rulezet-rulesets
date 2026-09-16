rule TTP_XOR_WriteProcessMemory_6fbc {
  strings:
    $key_6fbc = { 38 ce [2] 0a ec [2] 0c d9 [2] 22 d9 [2] 1d c5 }

  condition:
    any of them
}