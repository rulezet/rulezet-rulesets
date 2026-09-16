rule TTP_XOR_WriteProcessMemory_eebc {
  strings:
    $key_eebc = { b9 ce [2] 8b ec [2] 8d d9 [2] a3 d9 [2] 9c c5 }

  condition:
    any of them
}