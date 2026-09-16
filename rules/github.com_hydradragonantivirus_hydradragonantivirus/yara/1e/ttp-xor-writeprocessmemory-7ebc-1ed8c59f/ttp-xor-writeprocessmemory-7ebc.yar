rule TTP_XOR_WriteProcessMemory_7ebc {
  strings:
    $key_7ebc = { 29 ce [2] 1b ec [2] 1d d9 [2] 33 d9 [2] 0c c5 }

  condition:
    any of them
}