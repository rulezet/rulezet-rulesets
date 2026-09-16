rule TTP_XOR_WriteProcessMemory_1ebc {
  strings:
    $key_1ebc = { 49 ce [2] 7b ec [2] 7d d9 [2] 53 d9 [2] 6c c5 }

  condition:
    any of them
}