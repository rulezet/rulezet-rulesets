rule TTP_XOR_WriteProcessMemory_0fbc {
  strings:
    $key_0fbc = { 58 ce [2] 6a ec [2] 6c d9 [2] 42 d9 [2] 7d c5 }

  condition:
    any of them
}