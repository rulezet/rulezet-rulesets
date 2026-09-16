rule TTP_XOR_WriteProcessMemory_0ebc {
  strings:
    $key_0ebc = { 59 ce [2] 6b ec [2] 6d d9 [2] 43 d9 [2] 7c c5 }

  condition:
    any of them
}