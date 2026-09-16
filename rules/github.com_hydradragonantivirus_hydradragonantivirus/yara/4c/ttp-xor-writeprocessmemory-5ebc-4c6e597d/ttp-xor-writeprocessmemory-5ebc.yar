rule TTP_XOR_WriteProcessMemory_5ebc {
  strings:
    $key_5ebc = { 09 ce [2] 3b ec [2] 3d d9 [2] 13 d9 [2] 2c c5 }

  condition:
    any of them
}